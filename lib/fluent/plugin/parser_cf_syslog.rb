require "fluent/plugin/parser"
require "fluent/time"

module Fluent
  module Plugin
    class CloudFoundryParserSyslog < Parser
      Plugin.register_parser("cloudfoundry-syslog", self)

      # https://www.iana.org/assignments/enterprise-numbers/enterprise-numbers
      CF_IANA_ENTERPRISE_ID = 47450.freeze

      # Syslog Constants https://datatracker.ietf.org/doc/html/rfc5424#section-6
      SYSLOG_HEADER_SPLIT_CHAR = " ".freeze     # See SP
      SYSLOG_NILVALUE = "-".freeze              # See NILVALUE
      SYSLOG_PRI_DELIMITER_START = "<".freeze   # See PRI
      SYSLOG_PRI_DELIMITER_END = ">".freeze     # See PRI
      SYSLOG_SD_DELIMITER_START = "[".freeze    # See STRUCTURED-DATA
      SYSLOG_SD_DELIMITER_END = "]".freeze      # See STRUCTURED-DATA

      # https://datatracker.ietf.org/doc/html/rfc5424#section-6.2
      # PRI is parsed separately (https://datatracker.ietf.org/doc/html/rfc5424#section-6.2.1)
      SYSLOG_HEADER_FIELDS = [
        "version",    # https://datatracker.ietf.org/doc/html/rfc5424#section-6.2.2
        "timestamp",  # https://datatracker.ietf.org/doc/html/rfc5424#section-6.2.3
        "hostname",   # https://datatracker.ietf.org/doc/html/rfc5424#section-6.2.4
        "app_name",   # https://datatracker.ietf.org/doc/html/rfc5424#section-6.2.5
        "proc_id",    # https://datatracker.ietf.org/doc/html/rfc5424#section-6.2.6
        "msg_id",     # https://datatracker.ietf.org/doc/html/rfc5424#section-6.2.7
      ]

      # https://datatracker.ietf.org/doc/html/rfc5424#appendix-A.3
      # https://resources.docs.pivotal.io/pdfs/tiledev-guide-2.1.pdf
      SYSLOG_SEVERITY_CODES = [
        "emergency",
        "alert",
        "critical",
        "error",
        "warning",
        "notice",
        "info",
        "debug",
      ]

      # Regexes to extract information from STRUCTURED-DATA
      # Matches a whole STRUCTURED-DATA block including the delimiters '[', ']'
      SYSLOG_STRUCTURED_DATA_MATCH_REGEX = Regexp.new(/^(\[(?:[a-zA-Z_-]+(?:\@[0-9]+)?)*(?:[a-zA-Z0-9_-]+="(?:[^\\\]\"]|\\"|\\\]|\\\\|\\[^"\]\\])*"| )*\])/)
      # Matches the SD-ID if applied to the SYSLOG_STRUCTURED_DATA_MATCH_REGEX match
      SYSLOG_SD_ID_MATCH_REGEX = Regexp.new(/^\[([a-zA-Z0-9_-]+(?:\@[0-9]+)?)/)
      # Matches an SD-PARAM (SD-NAME=SD-VALUE)
      SYSLOG_SD_PARAM_MATCH_REGEX = Regexp.new(/([a-zA-Z0-9_-]+="(?:[^\\\]\"]|\\"|\\\]|\\\\|\\[^"\]\\])*")/)

      # Regex to extract information from Gorouter access logs
      # https://github.com/cloudfoundry/gorouter#access-logs
      # <Request Host> - [<Start Date>] "<Request Method> <Request URL> <Request Protocol>" <Status Code> <Bytes Received> <Bytes Sent> "<Referer>" "<User-Agent>" <Remote Address> <Backend Address> x_forwarded_for:"<X-Forwarded-For>" x_forwarded_proto:"<X-Forwarded-Proto>" vcap_request_id:<X-Vcap-Request-ID> response_time:<Response Time> gorouter_time:<Gorouter Time> app_id:<Application ID> app_index:<Application Index> x_cf_routererror:<X-Cf-RouterError> <Extra Headers>
      GOROUTER_MESSAGE_STATIC_REGEX = Regexp.new(/^(?<host>[^ ]+) - \[(?<timestamp>[^\]]+)\] "(?<method>[^ ]+) (?<pathname>[^ ]+) (?<protocol>[^"]+)" (?<status>[^ ]+) (?<bytes_received>[^ ]+) (?<bytes_sent>[^ ]+) "(?<referer>[^"]+)" "(?<user_agent>[^"]+)" "(?<remote_address>[^"]+)" "(?<backend_address>[^"]+)"/)
      GOROUTER_MESSAGE_EXTRADATA_REGEX = Regexp.new(/(?<param>[a-zA-Z0-9_-]+):(?<value>(?:[0-9\.]+|"[^"]+"|-))(?: |\n|\\|$)/)

      config_param :parse_gorouter_access_log, :bool, default: false
      config_param :include_raw_message, :bool, default: false

      @time_parser

      def initialize
        super
      end

      def configure(conf)
        super
        @time_parser = time_parser_create(format: "%Y-%m-%dT%H:%M:%S.%L%z")
      end

      def parse(text)
        if text.nil? or not text.start_with?(SYSLOG_PRI_DELIMITER_START)
          yield nil
          return
        end

        cursor = 0
        record = {}

        if @include_raw_message
          record["raw"] = text
        end

        # RFC 5424 currently only defines version 1
        # https://datatracker.ietf.org/doc/html/rfc5424#section-6.2.2
        record["header"], cursor = parse_header(text)
        if cursor.nil? or record.dig("header", "version") != "1"
          yield nil
          return
        end

        # Convert to integer for convenience
        record["header"]["version"] = 1

        # https://datatracker.ietf.org/doc/html/rfc5424#section-6.2.3
        time = @time_parser.parse(record["header"]["timestamp"]) rescue nil

        if time.nil?
          yield nil
          return
        end

        # Parse STRUCTURED_DATA
        record["sd"], cursor = parse_structured_data(text, cursor)
        if (cursor.nil?)
          yield nil
          return
        end

        # Parse MESSAGE
        msg = text.slice(cursor, text.length - cursor)

        if msg.nil?
          record["message"] = nil
        else
          record["message"] = msg.strip

          if @parse_gorouter_access_log and
             record.dig("sd", "tags@#{CF_IANA_ENTERPRISE_ID}", "origin") == "gorouter"
            record["gorouter"] = parse_gorouter_access_logs(record["message"])
          end
        end

        yield time, record
      end

      def parse_integer(str)
        return Integer(str || "")
      rescue ArgumentError
        return
      end

      def parse_header_block(text, startIdx)
        i = text.index(SYSLOG_HEADER_SPLIT_CHAR, startIdx)
        if i.nil? or i - startIdx < 1 then return end
        return text.slice(startIdx, i - startIdx), i + 1
      end

      # https://datatracker.ietf.org/doc/html/rfc5424#section-6.2.1
      def parse_pri(text)
        unless text.start_with?(SYSLOG_PRI_DELIMITER_START) then return end
        endIdx = text.index(SYSLOG_PRI_DELIMITER_END, 1)
        if endIdx.nil? or endIdx < 2 then return end
        v_pri = parse_integer(text.slice(1, endIdx - 1))
        if v_pri.nil? or v_pri < 0 then return end
        return v_pri >> 3, SYSLOG_SEVERITY_CODES[v_pri & 0b111], endIdx
      end

      # https://datatracker.ietf.org/doc/html/rfc5424#section-6.2
      def parse_header(text)
        facility, severity, c = parse_pri(text)
        if (c.nil?) then return end
        c = c + 1

        r = {
          "pri" => {
            "facility" => facility,
            "severity" => severity,
          },
        }

        SYSLOG_HEADER_FIELDS.each { |field|
          block, endIdx = parse_header_block(text, c)
          if block.nil? then return end
          r[field] = block
          c = endIdx
        }

        return r, c
      end

      # https://datatracker.ietf.org/doc/html/rfc5424#section-6.3.1
      def parse_sd_element(sd_element)
        sd_params = {}

        # https://datatracker.ietf.org/doc/html/rfc5424#section-6.3.2
        sd_id = sd_element[SYSLOG_SD_ID_MATCH_REGEX]
        if sd_id.nil? then return end
        sd_id = sd_id[1..-1]

        # https://datatracker.ietf.org/doc/html/rfc5424#section-6.3.3
        sd_element.scan(SYSLOG_SD_PARAM_MATCH_REGEX).each { |match|
          arr = match[0].strip.split("=", 2)
          sd_params[arr[0]] = arr[1][1..-2]
        }

        return sd_id, sd_params
      end

      # https://datatracker.ietf.org/doc/html/rfc5424#section-6.3
      def parse_structured_data(text, startIdx)
        if text[startIdx] == SYSLOG_NILVALUE then return {}, startIdx + 1 end
        unless text[startIdx] == SYSLOG_SD_DELIMITER_START then return end

        sd = text[startIdx..-1][SYSLOG_STRUCTURED_DATA_MATCH_REGEX]
        if sd.nil? then return end

        r = {}
        len = 0
        loop do
          len += sd.length
          sd_id, sd_params = parse_sd_element(sd)
          if sd_id.nil? then return end
          r[sd_id] = sd_params
          sd = text[startIdx + len..-1][SYSLOG_STRUCTURED_DATA_MATCH_REGEX]
          break if sd.nil?
        end

        return r, startIdx + len
      end

      # https://github.com/cloudfoundry/gorouter#access-logs
      def parse_gorouter_access_logs(msg)
        r = msg.match(GOROUTER_MESSAGE_STATIC_REGEX)
        if r.nil? then return end
        extra_headers = msg[r.to_s.length..-1]
        r = r.named_captures
        if extra_headers.nil? then return r end
        extra_headers.strip.scan(GOROUTER_MESSAGE_EXTRADATA_REGEX) { |match|
          unless match.length == 2 then next end
          if match[1].start_with?('"') and match[1].end_with?('"')
            # Strings
            r[match[0]] = match[1][1..-2]
          elsif match[1].match(/^[0-9]+(?:\.[0-9+]+)?$/)
            # Numbers
            r[match[0]] = match[1].to_f
          else
            r[match[0]] = match[1]
          end
        }
        return r
      end
    end
  end
end

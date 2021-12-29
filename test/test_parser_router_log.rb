require "test-unit"
require "fluent/test"
require "fluent/test/helpers"
require "fluent/test/driver/parser"
require "fluent/plugin/parser_cloudfoundry_syslog.rb"

class GorouterParserLog < Test::Unit::TestCase
  include Fluent::Test::Helpers

  def setup
    Fluent::Test.setup
    @parser = Fluent::Test::Driver::Parser.new(Fluent::Plugin::CloudFoundrySyslogParser)

    @parser.configure({
      "parse_gorouter_access_log" => true,
    })
  end

  def test_a
    log = %{
      <14>1 2021-12-24T22:20:01.438069+00:00 some-hostname some-appname [RTR/0] - 
      [tags@47450
        __v1_type="LogMessage" 
        app_id="some-app-id" 
        app_name="some-appname"
        component="route-emitter" 
        deployment="eu-gb-prod" 
        index="some-index" 
        instance_id="0" 
        ip="some-ip" 
        job="router" 
        organization_id="some-org-id" 
        organization_name="some-org-name" 
        origin="gorouter" 
        process_id="some-process-id" 
        process_instance_id="some-process-instance-id" 
        process_type="web"
        source_type="RTR"
        space_id="some-space-id" 
        space_name="dev"]
      example.com
      -
      [2021-12-24T22:20:01.429164095Z]
      "GET /styles.css HTTP/1.1"
      304
      0
      0
      "https://example.com/"
      "Mozilla/5.0 (X11; Fedora; Linux x86_64; rv:95.0) Gecko/20100101 Firefox/95.0" 
      "some-remote-host"
      "some-backend-host" 
      x_forwarded_for:"a, b"
      x_forwarded_proto:"https"
      vcap_request_id:"some-request-id"
      response_time:0.008452
      gorouter_time:0.000625
      app_id:"some-app-id" 
      app_index:"0" 
      instance_id:"some-instance-id"
      x_cf_routererror:"-" 
      x_global_transaction_id:"some-global-transaction-id"
      true_client_ip:"-"
      x_b3_traceid:"some-trace-id" 
      x_b3_spanid:"some-span-id"
      x_b3_parentspanid:"-" 
      b3:"some-b3"
    }.gsub(/\s+/, " ").strip
    @parser.instance.parse(log) { |time, record|
      assert_not_nil(time)
      assert_not_nil(record)
      assert_not_nil(record["gorouter"])
      assert_equal("LogMessage", record.dig("sd", "tags@47450", "__v1_type"))
      assert_equal("2021-12-24T22:20:01.429164095Z", record.dig("gorouter", "timestamp"))
      assert_equal("GET", record.dig("gorouter", "method"))
      assert_equal("/styles.css", record.dig("gorouter", "pathname"))
      assert_equal("HTTP/1.1", record.dig("gorouter", "protocol"))
      assert_equal("304", record.dig("gorouter", "status"))
      assert_equal("0", record.dig("gorouter", "bytes_received"))
      assert_equal("0", record.dig("gorouter", "bytes_sent"))
      assert_equal("https://example.com/", record.dig("gorouter", "referer"))
      assert_equal("Mozilla/5.0 (X11; Fedora; Linux x86_64; rv:95.0) Gecko/20100101 Firefox/95.0", record.dig("gorouter", "user_agent"))
      assert_equal("some-remote-host", record.dig("gorouter", "remote_address"))
      assert_equal("some-backend-host", record.dig("gorouter", "backend_address"))
      assert_equal("a, b", record.dig("gorouter", "x_forwarded_for"))
      assert_equal(0.000625, record.dig("gorouter", "gorouter_time"))
    }
  end
end

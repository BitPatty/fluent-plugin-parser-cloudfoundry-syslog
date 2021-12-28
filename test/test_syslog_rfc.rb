require "test-unit"
require "fluent/test"
require "fluent/test/helpers"
require "fluent/test/driver/parser"
require "fluent/plugin/parser_cf_syslog.rb"

class SyslogRFCTest < Test::Unit::TestCase
  include Fluent::Test::Helpers

  def setup
    Fluent::Test.setup
    @parser = Fluent::Test::Driver::Parser.new(Fluent::Plugin::CloudFoundryParserSyslog)
    @parser.configure({})
  end

  def test_nil
    @parser.instance.parse(nil) { |time, record|
      assert_nil(time)
      assert_nil(record)
    }
  end

  def test_empty_string
    @parser.instance.parse("") { |time, record|
      assert_nil(time)
      assert_nil(record)
    }
  end

  def test_words
    @parser.instance.parse("foo bar") { |time, record|
      assert_nil(time)
      assert_nil(record)
    }
  end

  def test_parse_syslog
    log = '<13>1 1985-04-12T23:20:50.52Z some-hostname some-appname some-procid some-msgid [instance@47450 paramA="def123" paramB="j k l" paramC=""] some foo bar'
    @parser.instance.parse(log) { |time, record|
      assert_not_nil(time)
      assert_not_nil(record)
      assert_equal(1, record.dig("header", "pri", "facility"))
      assert_equal(Fluent::Plugin::CloudFoundryParserSyslog::SYSLOG_SEVERITY_CODES[5], record.dig("header", "pri", "severity"))
      assert_equal("some-hostname", record.dig("header", "hostname"))
      assert_equal("some-appname", record.dig("header", "app_name"))
      assert_equal("some-procid", record.dig("header", "proc_id"))
      assert_equal("some-msgid", record.dig("header", "msg_id"))
      assert_equal({
        "paramA" => "def123",
        "paramB" => "j k l",
        "paramC" => "",
      }, record.dig("sd", "instance@47450"))
      assert_equal("some foo bar", record.dig("message"))
    }
  end

  def test_parse_syslog_with_nilvalue_structured_data
    log = "<13>1 1985-04-12T23:20:50.52Z some-hostname some-appname some-procid some-msgid - some foo bar"
    @parser.instance.parse(log) { |time, record|
      assert_not_nil(time)
      assert_not_nil(record)
      assert_equal(1, record.dig("header", "pri", "facility"))
      assert_equal(Fluent::Plugin::CloudFoundryParserSyslog::SYSLOG_SEVERITY_CODES[5], record.dig("header", "pri", "severity"))
      assert_equal("some-hostname", record.dig("header", "hostname"))
      assert_equal("some-appname", record.dig("header", "app_name"))
      assert_equal("some-procid", record.dig("header", "proc_id"))
      assert_equal("some-msgid", record.dig("header", "msg_id"))
      assert_equal({}, record.dig("sd"))
    }
  end

  def test_parse_syslog_with_sd_element_without_sd_params
    log = "<13>1 1985-04-12T23:20:50.52Z some-hostname some-appname some-procid some-msgid [instance] some foo bar"
    @parser.instance.parse(log) { |time, record|
      assert_not_nil(time)
      assert_not_nil(record)
      assert_equal(1, record.dig("header", "pri", "facility"))
      assert_equal(Fluent::Plugin::CloudFoundryParserSyslog::SYSLOG_SEVERITY_CODES[5], record.dig("header", "pri", "severity"))
      assert_equal("some-hostname", record.dig("header", "hostname"))
      assert_equal("some-appname", record.dig("header", "app_name"))
      assert_equal("some-procid", record.dig("header", "proc_id"))
      assert_equal("some-msgid", record.dig("header", "msg_id"))
      assert_equal({ "instance" => {} }, record.dig("sd"))
    }
  end

  def test_parse_syslog_with_sd_element_with_registered_id
    log = "<13>1 1985-04-12T23:20:50.52Z some-hostname some-appname some-procid some-msgid [instance@1234] some foo bar"
    @parser.instance.parse(log) { |time, record|
      assert_not_nil(time)
      assert_not_nil(record)
      assert_equal(1, record.dig("header", "pri", "facility"))
      assert_equal(Fluent::Plugin::CloudFoundryParserSyslog::SYSLOG_SEVERITY_CODES[5], record.dig("header", "pri", "severity"))
      assert_equal("some-hostname", record.dig("header", "hostname"))
      assert_equal("some-appname", record.dig("header", "app_name"))
      assert_equal("some-procid", record.dig("header", "proc_id"))
      assert_equal("some-msgid", record.dig("header", "msg_id"))
      assert_equal({ "instance@1234" => {} }, record.dig("sd"))
    }
  end

  def test_parse_syslog_with_escapes_in_sd_value
    log = '<13>1 1985-04-12T23:20:50.52Z some-hostname some-appname some-procid some-msgid [instance@47450 paramA="def\\12\\3" paramB="j k l\\"" paramC="\\"\\]"] some foo bar'
    @parser.instance.parse(log) { |time, record|
      assert_not_nil(time)
      assert_not_nil(record)
      assert_equal(1, record.dig("header", "pri", "facility"))
      assert_equal(Fluent::Plugin::CloudFoundryParserSyslog::SYSLOG_SEVERITY_CODES[5], record.dig("header", "pri", "severity"))
      assert_equal("some-hostname", record.dig("header", "hostname"))
      assert_equal("some-appname", record.dig("header", "app_name"))
      assert_equal("some-procid", record.dig("header", "proc_id"))
      assert_equal("some-msgid", record.dig("header", "msg_id"))
      assert_equal({
        "paramA" => "def\\12\\3",
        "paramB" => "j k l\\\"",
        "paramC" => "\\\"\\]",
      }, record.dig("sd", "instance@47450"))
      assert_equal("some foo bar", record.dig("message"))
    }
  end

  def test_parse_syslog_with_invalid_escapes_in_sd_value
    log = '<13>1 1985-04-12T23:20:50.52Z some-hostname some-appname some-procid some-msgid [instance@47450 paramB="j k l\\\\""] some foo bar'
    @parser.instance.parse(log) { |time, record|
      assert_nil(time)
      assert_nil(record)
    }
  end

  def test_parse_syslog_with_invalid_escaped_sd_value_delimiter
    log = '<13>1 1985-04-12T23:20:50.52Z some-hostname some-appname some-procid some-msgid [instance@47450 paramC="\\"] some foo bar'
    @parser.instance.parse(log) { |time, record|
      assert_nil(time)
      assert_nil(record)
    }
  end

  def test_parse_syslog_with_multiple_sd_elements
    log = '<13>1 1985-04-12T23:20:50.52Z some-hostname some-appname some-procid some-msgid [elementA fooA="barA"][elementB fooB="barB"] some foo bar'
    @parser.instance.parse(log) { |time, record|
      assert_not_nil(time)
      assert_not_nil(record)
      assert_equal(1, record.dig("header", "pri", "facility"))
      assert_equal(Fluent::Plugin::CloudFoundryParserSyslog::SYSLOG_SEVERITY_CODES[5], record.dig("header", "pri", "severity"))
      assert_equal("some-hostname", record.dig("header", "hostname"))
      assert_equal("some-appname", record.dig("header", "app_name"))
      assert_equal("some-procid", record.dig("header", "proc_id"))
      assert_equal("some-msgid", record.dig("header", "msg_id"))
      assert_equal({
        "elementA" => {
          "fooA" => "barA",
        },
        "elementB" => {
          "fooB" => "barB",
        },
      }, record.dig("sd"))
      assert_equal("some foo bar", record.dig("message"))
    }
  end

  def test_parse_syslog_with_seperated_sd_elements
    log = '<13>1 1985-04-12T23:20:50.52Z some-hostname some-appname some-procid some-msgid [elementA fooA="barA"] [elementB fooB="barB"] some foo bar'
    @parser.instance.parse(log) { |time, record|
      assert_not_nil(time)
      assert_not_nil(record)
      assert_equal(1, record.dig("header", "pri", "facility"))
      assert_equal(Fluent::Plugin::CloudFoundryParserSyslog::SYSLOG_SEVERITY_CODES[5], record.dig("header", "pri", "severity"))
      assert_equal("some-hostname", record.dig("header", "hostname"))
      assert_equal("some-appname", record.dig("header", "app_name"))
      assert_equal("some-procid", record.dig("header", "proc_id"))
      assert_equal("some-msgid", record.dig("header", "msg_id"))
      assert_equal({
        "elementA" => {
          "fooA" => "barA",
        },
      }, record.dig("sd"))
      assert_equal('[elementB fooB="barB"] some foo bar', record.dig("message"))
    }
  end

  def test_parse_syslog_without_message
    log = '<13>1 1985-04-12T23:20:50.52Z some-hostname some-appname some-procid some-msgid [instance@47450 paramA="def123" paramB="j k l" paramC=""]'
    @parser.instance.parse(log) { |time, record|
      assert_not_nil(time)
      assert_not_nil(record)
      assert_equal(1, record.dig("header", "pri", "facility"))
      assert_equal(Fluent::Plugin::CloudFoundryParserSyslog::SYSLOG_SEVERITY_CODES[5], record.dig("header", "pri", "severity"))
      assert_equal("some-hostname", record.dig("header", "hostname"))
      assert_equal("some-appname", record.dig("header", "app_name"))
      assert_equal("some-procid", record.dig("header", "proc_id"))
      assert_equal("some-msgid", record.dig("header", "msg_id"))
      assert_equal({
        "paramA" => "def123",
        "paramB" => "j k l",
        "paramC" => "",
      }, record.dig("sd", "instance@47450"))
      assert_equal("", record.dig("message"))
    }
  end

  def test_parse_syslog_with_nilvalue_sd_without_message
    log = "<13>1 1985-04-12T23:20:50.52Z some-hostname some-appname some-procid some-msgid -"
    @parser.instance.parse(log) { |time, record|
      assert_not_nil(time)
      assert_not_nil(record)
      assert_equal(1, record.dig("header", "pri", "facility"))
      assert_equal(Fluent::Plugin::CloudFoundryParserSyslog::SYSLOG_SEVERITY_CODES[5], record.dig("header", "pri", "severity"))
      assert_equal("some-hostname", record.dig("header", "hostname"))
      assert_equal("some-appname", record.dig("header", "app_name"))
      assert_equal("some-procid", record.dig("header", "proc_id"))
      assert_equal("some-msgid", record.dig("header", "msg_id"))
      assert_equal({}, record.dig("sd"))
      assert_equal("", record.dig("message"))
    }
  end
end

# fluent-plugin-parser-cloudfoundry-syslog

A experimental, work-in-progress [fluentd](https://www.fluentd.org/) parser for CloudFoundry specific syslog drains - basically the opposite end of their [output formatter](https://github.com/cloudfoundry/fluent-plugin-syslog_rfc5424).

This plugin should make CF metrics more accessible than the current [syslog parser for fluent](https://docs.fluentd.org/parser/syslog) allows for.


## Sample

An access log in the format

```
<14>1 2021-12-24T22:20:01.438069+00:00 some-hostname some-appname [RTR/0] - [tags@47450 __v1_type="LogMessage" app_id="some-app-id" app_name="some-appname" component="route-emitter" deployment="eu-gb-prod" index="some-index" instance_id="0" ip="some-ip" job="router" organization_id="some-org-id" organization_name="some-org-name" origin="gorouter" process_id="some-process-id" process_instance_id="some-process-instance-id" process_type="web" source_type="RTR" space_id="some-space-id" space_name="dev"] example.com - [2021-12-24T22:20:01.429164095Z] "GET /styles.css HTTP/1.1" 304 0 0 "https://example.com/" "Mozilla/5.0 (X11; Fedora; Linux x86_64; rv:95.0) Gecko/20100101 Firefox/95.0" "some-remote-host" "some-backend-host" x_forwarded_for:"a, b" x_forwarded_proto:"https" vcap_request_id:"some-request-id" response_time:0.008452 gorouter_time:0.000625 app_id:"some-app-id" app_index:"0" instance_id:"some-instance-id" x_cf_routererror:"-" x_global_transaction_id:"some-global-transaction-id" true_client_ip:"-" x_b3_traceid:"some-trace-id" x_b3_spanid:"some-span-id" x_b3_parentspanid:"-" b3:"some-b3"
```

.. is turned into ..

```ruby
{
  "header" => {
    "pri" => {
      "facility" => 1,
      "severity" => "info",
    },
    "version" => 1,
    "timestamp" => "2021-12-24T22:20:01.438069+00:00",
    "hostname" => "some-hostname",
    "app_name" => "some-appname",
    "proc_id" => "[RTR/0]",
    "msg_id" => "-",
  },
  "sd" => {
    "tags@47450" => {
      "__v1_type" => "LogMessage",
      "app_id" => "some-app-id",
      "app_name" => "some-appname",
      "component" => "route-emitter",
      "deployment" => "eu-gb-prod",
      "index" => "some-index",
      "instance_id" => "0",
      "ip" => "some-ip",
      "job" => "router",
      "organization_id" => "some-org-id",
      "organization_name" => "some-org-name",
      "origin" => "gorouter",
      "process_id" => "some-process-id",
      "process_instance_id" => "some-process-instance-id",
      "process_type" => "web",
      "source_type" => "RTR",
      "space_id" => "some-space-id",
      "space_name" => "dev",
    },
  },
  "gorouter" => {
    "host" => "example.com",
    "timestamp" => "2021-12-24T22:20:01.429164095Z",
    "method" => "GET",
    "pathname" => "/styles.css",
    "protocol" => "HTTP/1.1",
    "status" => "304",
    "bytes_received" => "0",
    "bytes_sent" => "0",
    "referer" => "https://example.com/",
    "user_agent" => "Mozilla/5.0 (X11; Fedora; Linux x86_64; rv:95.0) Gecko/20100101 Firefox/95.0",
    "remote_address" => "some-remote-host",
    "backend_address" => "some-backend-host",
    "x_forwarded_for" => "a, b",
    "x_forwarded_proto" => "https",
    "vcap_request_id" => "some-request-id",
    "response_time" => 0.008452,
    "gorouter_time" => 0.000625,
    "app_id" => "some-app-id",
    "app_index" => "0",
    "instance_id" => "some-instance-id",
    "x_cf_routererror" => "-",
    "x_global_transaction_id" => "some-global-transaction-id",
    "true_client_ip" => "-",
    "x_b3_traceid" => "some-trace-id",
    "x_b3_spanid" => "some-span-id",
    "x_b3_parentspanid" => "-",
    "b3" => "some-b3",
  },
  "message" => 'example.com - [2021-12-24T22:20:01.429164095Z] "GET /styles.css HTTP/1.1" 304 0 0 "https://example.com/" "Mozilla/5.0 (X11; Fedora; Linux x86_64; rv:95.0) Gecko/20100101 Firefox/95.0" "some-remote-host" "some-backend-host" x_forwarded_for:"a, b" x_forwarded_proto:"https" vcap_request_id:"some-request-id" response_time:0.008452 gorouter_time:0.000625 app_id:"some-app-id" app_index:"0" instance_id:"some-instance-id" x_cf_routererror:"-" x_global_transaction_id:"some-global-transaction-id" true_client_ip:"-" x_b3_traceid:"some-trace-id" x_b3_spanid:"some-span-id" x_b3_parentspanid:"-" b3:"some-b3"',
}
```

## Usage

Install the plugin:

```sh
# See https://github.com/BitPatty/fluent-plugin-parser-cloudfoundry-syslog/releases for a list of valid versions
gem install fluent-plugin-parser-cloudfoundry-syslog --version "<desired version>"
```

Create a logdrain and update your fluent configuration:

```conf
<source>
  # Use TCP or HTTP, depending on what your logdrain is
  # configured to use
  @type http

  # Your source configuration...

  <parse>
    @type cloudfoundry_syslog

    # Set this to true if access log messages should be parsed.
    # Defaults to false
    parse_gorouter_access_log true

    # Set this to true if you want the raw message to be available
    # under the key `raw`. Defaults to false
    include_raw_message true
  </parse>
</source>
```

## Limitations

- ~~Values in `STRUCTURED-DATA`, such as app names, may not contain quotes since they're not being escaped on CloudFoundry's side. See https://github.com/cloudfoundry/loggregator-agent-release/issues/69~~ => should be fixed with https://github.com/cloudfoundry/loggregator-agent-release/releases/tag/v6.3.7

## Credit

- [fluent-plugin-elasticsearch](https://github.com/uken/fluent-plugin-elasticsearch) used as reference for boilerplating the codebase and GH workflows
- [fluentd/parser_syslog](https://github.com/fluent/fluentd/blob/master/lib/fluent/plugin/parser_syslog.rb) used as reference on the current builtin syslog parser

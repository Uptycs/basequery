# basequery

basequery is a trimmed down version of [Osquery](https://osquery.io). Checkout Osquery [README](https://github.com/osquery/osquery/blob/master/README.md) first.

## Differences?

[kubequery](https://github.com/Uptycs/kubequery/), [cloudquery](https://github.com/Uptycs/cloudquery/), etc are Osquery extensions. When developing these, there were some shortcomings with Osquery extension model. Also, a lot of the [tables](https://osquery.io/schema/) in Osquery are not relevant to these tools.

So basequery is forked off of Osquery to create a light weight version. Some feature gaps in extension support are also implemented in basequery.

* Removed most of the tables, carving, ATC with the exception of the following:
  * osquery_events
  * osquery_extensions
  * osquery_flags
  * osquery_info
  * osquery_packs
  * osquery_registry
  * osquery_schedule
  * time
  * processes (not required in basequery but internally used by watcher)
* Removed dependencies on third-party libraries that are no longer needed
* Enroll plugin contents are customizable
* Extensions can have their own flags
* Extensions can create evented tables and stream event data

### Enroll contents

Osquery sends the contents of the following tables as a part of the enroll request:
* os_version
* osquery_info
* system_info
* platform_info

basequery, by default will only send `osquery_info` table data. This can be changed using `--enroll_tables` flag. For example: `--enroll_tables=osquery_info,kubernetes_info` will send `osquery_info` and `kubernetes_info` data during enrollment process.

### Extension flags

Osquery does not allow undefined flags. If one is passed on command line or via flags file, Osquery will refuse to start. In basequery new flag `--extensions_flags` can be used to define extension specific flags.

For example: `--extensions_flags=kubequery_flag1,kubequery_flag2` will allow basequery to parse `--kubequery_flag1` and `--kubequery_flag2` flags. Extensions can use `options()` to retrive the flag values. By default all extension flags are defined as `string`.

### Extension event tables

Event'ed table can be implemented in extension just like any regular table.

* Name of the table should end with `_events`
* Comma separated list of event tables should be passed to basequery using `--extension_event_tables` flag. For example: `--extension_event_tables=kubernetes_events,pod_events`. This flag enables basequery to start the publisher thread for each extension events table
* `generate` method will never be called in extension events table
* Table implementation should call `streamEvents` whenever it has data available
* If there is a timestamp available for the event, it should be defined in a column called `time`. It should hold the time of the event as big integer

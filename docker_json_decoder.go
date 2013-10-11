package heka_andrewh_plugins

import (
	"encoding/json"
	"fmt"
	"github.com/mozilla-services/heka/pipeline"
	"regexp"
	"time"
)

func init() {
	pipeline.RegisterPlugin("DockerJsonDecoder",
		func() interface{} {
			return new(DockerJsonDecoder)
		},
	)
}

type DockerJsonDecoderConfig struct {
	// Regular expression that describes log line format and capture group
	// values.
	JsonMap map[string]string `toml:"json_map"`

	// Maps severity strings to their int version
	SeverityMap map[string]int32 `toml:"severity_map"`

	// Keyed to the message field that should be filled in, the value will be
	// interpolated so it can use capture parts from the message match.
	MessageFields pipeline.MessageTemplate `toml:"message_fields"`

	// User specified timestamp layout string, used for parsing a timestamp
	// string into an actual time object. If not specified or it fails to
	// match, all the default time layout's will be tried.
	TimestampLayout string `toml:"timestamp_layout"`

	// Time zone in which the timestamps in the text are presumed to be in.
	// Should be a location name corresponding to a file in the IANA Time Zone
	// database (e.g. "America/Los_Angeles"), as parsed by Go's
	// `time.LoadLocation()` function (see
	// http://golang.org/pkg/time/#LoadLocation). Defaults to "UTC". Not
	// required if valid time zone info is embedded in every parsed timestamp,
	// since those can be parsed as specified in the `timestamp_layout`.
	TimestampLocation string `toml:"timestamp_location"`
}

type DockerJsonDecoder struct {
	JsonMap         map[string]string
	SeverityMap     map[string]int32
	MessageFields   pipeline.MessageTemplate
	TimestampLayout string
	tzLocation      *time.Location
	dRunner         pipeline.DecoderRunner
}

type DockerJsonFormat struct {
	Log    string
	Stream string
	Time   string
}

func (ld *DockerJsonDecoder) ConfigStruct() interface{} {
	return &DockerJsonDecoderConfig{
		TimestampLayout: "2012-04-23T18:25:43.511Z",
	}
}

func (ld *DockerJsonDecoder) Init(config interface{}) (err error) {
	conf := config.(*DockerJsonDecoderConfig)

	ld.JsonMap = make(map[string]string)
	for capture_name, jp := range conf.JsonMap {
		ld.JsonMap[capture_name] = jp
	}

	ld.SeverityMap = make(map[string]int32)
	ld.MessageFields = make(pipeline.MessageTemplate)
	if conf.SeverityMap != nil {
		for codeString, codeInt := range conf.SeverityMap {
			ld.SeverityMap[codeString] = codeInt
		}
	}
	if conf.MessageFields != nil {
		for field, action := range conf.MessageFields {
			ld.MessageFields[field] = action
		}
	}
	ld.TimestampLayout = conf.TimestampLayout
	if ld.tzLocation, err = time.LoadLocation(conf.TimestampLocation); err != nil {
		err = fmt.Errorf("DockerJsonDecoder unknown timestamp_location '%s': %s",
			conf.TimestampLocation, err)
	}
	return
}

// Heka will call this to give us access to the runner.
func (ld *DockerJsonDecoder) SetDecoderRunner(dr pipeline.DecoderRunner) {
	ld.dRunner = dr
}

// Matches the given string against the JSONPath and returns the match result
// and captures
func (ld *DockerJsonDecoder) match(s string) (captures map[string]string) {
	captures = make(map[string]string)

	jp := new(pipeline.JsonPath)
	jp.SetJsonText(s)

	for capture_group, jpath := range ld.JsonMap {
		node_val, err := jp.Find(jpath)
		if err != nil {
			continue
		}
		captures[capture_group] = node_val
	}
	return
}

// Runs the message payload against decoder's map of JSONPaths. If
// there's a match, the message will be populated based on the
// decoder's message template, with capture values interpolated into
// the message template values.
func (ld *DockerJsonDecoder) Decode(pack *pipeline.PipelinePack) (err error) {

	var dockerLog DockerJsonFormat

	jsonErr := json.Unmarshal([]byte(pack.Message.GetPayload()), &dockerLog)
	if jsonErr != nil {
		return jsonErr
	}
	re := regexp.MustCompile("(\\\\)[^nt]")
	unescaped := re.ReplaceAllLiteralString(dockerLog.Log, "")

	captures := ld.match(unescaped)

	pdh := new(pipeline.PayloadDecoderHelper)
	pdh.Captures = captures
	pdh.TimestampLayout = ld.TimestampLayout
	pdh.TzLocation = ld.tzLocation
	pdh.SeverityMap = ld.SeverityMap

	pdh.DecodeTimestamp(pack)
	pdh.DecodeSeverity(pack)

	// Update the new message fields based on the fields we should
	// change and the capture parts
	pack.Message.SetPayload(unescaped)
	return ld.MessageFields.PopulateMessage(pack.Message, captures)
}

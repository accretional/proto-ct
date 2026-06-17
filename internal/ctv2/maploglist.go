package ctv2

import (
	pb "github.com/accretional/proto-ct/gen/ctingestion/v2"
	"github.com/google/certificate-transparency-go/loglist3"
)

// mapLogList converts a parsed loglist3.LogList into the proto CTLogList,
// unifying RFC 6962 logs and Static CT ("tiled") logs.
func mapLogList(ll *loglist3.LogList) *pb.CTLogList {
	out := &pb.CTLogList{
		Version:            ll.Version,
		LogListTimestampMs: ll.LogListTimestamp.UnixMilli(),
		IsAllLogs:          ll.IsAllLogs,
	}
	for _, op := range ll.Operators {
		o := &pb.CTLogOperator{Name: op.Name, Email: op.Email}
		for _, lg := range op.Logs {
			o.Logs = append(o.Logs, mapRFC6962Log(lg))
		}
		for _, lg := range op.TiledLogs {
			o.Logs = append(o.Logs, mapTiledLog(lg))
		}
		out.Operators = append(out.Operators, o)
	}
	return out
}

func mapRFC6962Log(lg *loglist3.Log) *pb.CTLog {
	state, ts := mapState(lg.State)
	return &pb.CTLog{
		LogId:            lg.LogID,
		Key:              lg.Key,
		Description:      lg.Description,
		Protocol:         pb.LogProtocol_LOG_PROTOCOL_RFC6962,
		Url:              lg.URL,
		MmdSeconds:       lg.MMD,
		LogType:          lg.Type,
		State:            state,
		StateTimestampMs: ts,
		TemporalInterval: mapTemporal(lg.TemporalInterval),
	}
}

func mapTiledLog(lg *loglist3.TiledLog) *pb.CTLog {
	state, ts := mapState(lg.State)
	return &pb.CTLog{
		LogId:            lg.LogID,
		Key:              lg.Key,
		Description:      lg.Description,
		Protocol:         pb.LogProtocol_LOG_PROTOCOL_STATIC_CT_API,
		SubmissionUrl:    lg.SubmissionURL,
		MonitoringUrl:    lg.MonitoringURL,
		MmdSeconds:       lg.MMD,
		LogType:          lg.Type,
		State:            state,
		StateTimestampMs: ts,
		TemporalInterval: mapTemporal(lg.TemporalInterval),
	}
}

func mapTemporal(ti *loglist3.TemporalInterval) *pb.TemporalInterval {
	if ti == nil {
		return nil
	}
	return &pb.TemporalInterval{
		StartInclusiveMs: ti.StartInclusive.UnixMilli(),
		EndExclusiveMs:   ti.EndExclusive.UnixMilli(),
	}
}

// mapState returns the single active state and its onset timestamp (ms).
func mapState(st *loglist3.LogStates) (pb.CTLogState, int64) {
	if st == nil {
		return pb.CTLogState_CT_LOG_STATE_UNSPECIFIED, 0
	}
	switch {
	case st.Pending != nil:
		return pb.CTLogState_CT_LOG_STATE_PENDING, st.Pending.Timestamp.UnixMilli()
	case st.Qualified != nil:
		return pb.CTLogState_CT_LOG_STATE_QUALIFIED, st.Qualified.Timestamp.UnixMilli()
	case st.Usable != nil:
		return pb.CTLogState_CT_LOG_STATE_USABLE, st.Usable.Timestamp.UnixMilli()
	case st.ReadOnly != nil:
		return pb.CTLogState_CT_LOG_STATE_READONLY, st.ReadOnly.Timestamp.UnixMilli()
	case st.Retired != nil:
		return pb.CTLogState_CT_LOG_STATE_RETIRED, st.Retired.Timestamp.UnixMilli()
	case st.Rejected != nil:
		return pb.CTLogState_CT_LOG_STATE_REJECTED, st.Rejected.Timestamp.UnixMilli()
	}
	return pb.CTLogState_CT_LOG_STATE_UNSPECIFIED, 0
}

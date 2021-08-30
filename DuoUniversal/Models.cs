using System;

namespace DuoUniversal
{

    internal class HealthCheckResponse
    {
        public string Stat { get; set; }
        public HealthCheckResponseDetail Response { get; set; }
    }

    internal class HealthCheckResponseDetail
    {
        public int Timestamp { get; set; }
        public string Code { get; set; }
        public string Message { get; set; }
        // [DataMember(Name = "message_detail")] // TODO this didn't work, figure it out
        public string Message_detail { get; set; }
    }
 
}

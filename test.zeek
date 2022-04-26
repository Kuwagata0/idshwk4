@load base/frameworks/sumstats

event zeek_init()
{
    local r404 = SumStats::Reducer($stream="http_response_404", $apply=set(SumStats::UNIQUE));
    local r = SumStats::Reducer($stream="http_response", $apply=set(SumStats::UNIQUE));
    SumStats::create(
        [$name = "http_scanning",
         $epoch = 10min,
         $reducers = set(r404, r),
         $epoch_result(ts: time, key: SumStats::Key, result: SumStats::Result) =
                        {   
                            local r1 = result["http_response_404"];
                            local r2 = result["http_response"];
                            if( r1$num > 2 && 
                                r1$num * 5 > r2$num &&
                                r1$unique * 2 > r1$num 
                                #int type 
                                #not invert to double type when calculating...
                            )
                            print fmt("%s is a scanner with %s scan attempts on %d urls", key$host, r1$num, r1$unique);
                        }
        ]
    );
}

event http_reply(c: connection, version: string, code: count, reason: string)
{
    if(code == 404) 
    {
        SumStats::observe("http_response_404",
        SumStats::Key($host = c$id$orig_h),
        SumStats::Observation($str=c$http$uri));
    }
    SumStats::observe("http_response",
    SumStats::Key($host = c$id$orig_h),
    SumStats::Observation($str=c$http$uri));
}
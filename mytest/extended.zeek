module ExtensionStats;

export {
    type ExtensionInfo: record {
        ts: time &log;
        uid: string &log;
        id: conn_id &log;

        min_fwd_pkt_len: double &optional &log;
        max_fwd_pkt_len: double &optional &log;
        mean_fwd_pkt_len: double &optional &log;
        median_fwd_pkt_len: double &optional &log;
        mad_fwd_pkt_len: double &optional &log;
        std_fwd_pkt_len: double &optional &log;
        skew_fwd_pkt_len: double &optional &log;
        kurt_fwd_pkt_len: double &optional &log;

        min_bwd_pkt_len: double &optional &log;
        max_bwd_pkt_len: double &optional &log;
        mean_bwd_pkt_len: double &optional &log;
        median_bwd_pkt_len: double &optional &log;
        mad_bwd_pkt_len: double &optional &log;
        std_bwd_pkt_len: double &optional &log;
        skew_bwd_pkt_len: double &optional &log;
        kurt_bwd_pkt_len: double &optional &log;

        min_fwd_pkt_interval: interval &optional &log;
        max_fwd_pkt_interval: interval &optional &log;
        mean_fwd_pkt_interval: interval &optional &log;
        median_fwd_pkt_interval: interval &optional &log;
        mad_fwd_pkt_interval: interval &optional &log;
        std_fwd_pkt_interval: interval &optional &log;
        skew_fwd_pkt_interval: double &optional &log;
        kurt_fwd_pkt_interval: double &optional &log;

        min_bwd_pkt_interval: interval &optional &log;
        max_bwd_pkt_interval: interval &optional &log;
        mean_bwd_pkt_interval: interval &optional &log;
        median_bwd_pkt_interval: interval &optional &log;
        mad_bwd_pkt_interval: interval &optional &log;
        std_bwd_pkt_interval: interval &optional &log;
        skew_bwd_pkt_interval: double &optional &log;
        kurt_bwd_pkt_interval: double &optional &log;

        fwd_psh_count: count &optional &log;
        bwd_psh_count: count &optional &log;

        fwd_bitrate: double &optional &log;
        bwd_bitrate: double &optional &log;

        #fwd_pkt_len_info: vector of count &optional &log;
        #bwd_pkt_len_info: vector of count &optional &log;
        #bwd_interval_info: vector of interval &optional &log;
        #fwd_interval_info: vector of interval &optional &log;
    };
}

redef enum Log::ID += { LOG_PacketStats };
event zeek_init()
{
    Log::create_stream(LOG_PacketStats, [$columns=ExtensionInfo, $path="extended_features"]);
}

# Forward/backward packet_size tracking
global fwd_pkt_lengths: table[conn_id] of vector of count;
global bwd_pkt_lengths: table[conn_id] of vector of count;

# Forward/backward time tracking
global last_pkt_time_fwd: table[conn_id] of time;
global last_pkt_time_bwd: table[conn_id] of time;
global intervals_fwd: table[conn_id] of vector of interval;
global intervals_bwd: table[conn_id] of vector of interval;

global fwd_psh_counts: table[conn_id] of count;
global bwd_psh_counts: table[conn_id] of count;

global first_pkt_time_fwd: table[conn_id] of time;
global first_pkt_time_bwd: table[conn_id] of time;

event tcp_packet(c: connection, is_orig: bool, flags: string, seq: count, ack: count, len: count, payload: string)
{
    local id = c$id;
    local now = network_time();

    # packet size
    if (is_orig) {
        if (id !in fwd_pkt_lengths){
            fwd_pkt_lengths[id] = vector();
            first_pkt_time_fwd[id] = now;
        }
        fwd_pkt_lengths[id] += len;
    }
    else {
        if (id !in bwd_pkt_lengths){
            bwd_pkt_lengths[id] = vector();
            first_pkt_time_bwd[id] = now;
        }
        bwd_pkt_lengths[id] += len;
    }

    # packet interval
    
    local last_table = is_orig ? last_pkt_time_fwd : last_pkt_time_bwd;
    local intervals_table = is_orig ? intervals_fwd : intervals_bwd;

    if (id !in last_table) {
        last_table[id] = now;
        intervals_table[id] = vector();
        return;
    }

    local delta = now - last_table[id];
    last_table[id] = now;

    if (id !in intervals_table)
        intervals_table[id] = vector();

    intervals_table[id] += delta;

    # packet flags
    if ( /P/ in flags ) {
        if (is_orig) {
            if (id !in fwd_psh_counts)
                fwd_psh_counts[id] = 0;
            fwd_psh_counts[id] += 1;
        }
        else {
            if (id !in bwd_psh_counts)
                bwd_psh_counts[id] = 0;
            bwd_psh_counts[id] += 1;
        }
    }

    
}

event udp_request(u: connection)
{
    local id = u$id;
    # 这里将请求方向作为 forward，响应方向作为 backward
    if (id !in fwd_pkt_lengths)
        fwd_pkt_lengths[id] = vector();
    if (id !in bwd_pkt_lengths)
        bwd_pkt_lengths[id] = vector();

    fwd_pkt_lengths[id] += u$orig$size;
    bwd_pkt_lengths[id] += u$resp$size;

    local now = network_time();
    if (id !in last_pkt_time_fwd) {
        last_pkt_time_fwd[id] = now;
        intervals_fwd[id] = vector();
    } else {
        local delta = now - last_pkt_time_fwd[id];
        last_pkt_time_fwd[id] = now;
        intervals_fwd[id] += delta;
    }   
}

event udp_reply(u: connection)
{
    local id = u$id;
    local now = network_time();
    if (id !in last_pkt_time_bwd) {
        last_pkt_time_bwd[id] = now;
        intervals_bwd[id] = vector();
    } else {
        local delta = now - last_pkt_time_bwd[id];
        last_pkt_time_bwd[id] = now;
        intervals_bwd[id] += delta;
    }
}

function min(x: double, y: double): double { return x < y ? x : y; }
function max(x: double, y: double): double { return x > y ? x : y; }
function abs(x: double): double { return x >= 0.0 ? x : -x; }
function cube(x: double): double { return x * x * x; }
function forth(x: double): double { return x * x * x * x; }
function sqr(x: double): double { return x * x; }

function compute_stats_unified(vals: vector of double): table[string] of double
{
    local stats: table[string] of double;
    local n = |vals|;
    if (n == 0) return stats;

    local total = 0.0;
    local min_val: double;
    local max_val: double;
    local visited = F;
    local sorted_vals: vector of double;

    for (i in vals) {
        local val = vals[i];
        total += val;
        if (!visited) {
            min_val = val;
            max_val = val;
            visited = T;
        } else {
            min_val = min(val, min_val);
            max_val = max(val, max_val);
        }
        sorted_vals += val;
    }

    stats["min"] = min_val;
    stats["max"] = max_val;

    local mean = total / n;
    stats["mean"] = mean;

    sort(sorted_vals);
    local median = (n % 2 == 0) ?
        (sorted_vals[n/2 - 1] + sorted_vals[n/2]) / 2.0 :
        sorted_vals[n/2];
    stats["median"] = median;

    local mad_vals: vector of double;
    for (i in sorted_vals)
        mad_vals += abs(sorted_vals[i] - median);

    sort(mad_vals);
    local mad = (n % 2 == 0) ?
        (mad_vals[n/2 - 1] + mad_vals[n/2]) / 2.0 :
        mad_vals[n/2];
    stats["mad"] = mad;

    local var = 0.0;
    for (i in sorted_vals)
        var += sqr(sorted_vals[i] - mean);
    var = var / n;
    stats["std"] = sqrt(var);

    local skew = 0.0;
    for (i in sorted_vals)
        skew += cube(sorted_vals[i] - mean);
    stats["skew"] = (stats["std"] == 0.0) ? 0.0 : skew / (n * cube(stats["std"]));

    local kurt = 0.0;
    for (i in sorted_vals)
        kurt += forth(sorted_vals[i] - mean);
    stats["kurt"] = (stats["std"] == 0.0) ? 0.0 : kurt / (n * var * var) - 3;

    return stats;
}

function compute_len_stats(v: vector of count): table[string] of double
{
    local converted: vector of double;
    for (i in v)
        converted += 1.0 * v[i];

    return compute_stats_unified(converted);
}

function compute_intv_stats(v: vector of interval): table[string] of double
{
    local converted: vector of double;
    for (i in v)
        converted += v[i] / 1sec;

    return compute_stats_unified(converted);
}

event connection_state_remove(c: connection)
{
    local id = c$id;
    local entry: ExtensionInfo = [$ts=network_time(), $uid=c$uid, $id=id];

    if (id in fwd_pkt_lengths && |fwd_pkt_lengths[id]| > 0) {
        local fwd_size_stats = compute_len_stats(fwd_pkt_lengths[id]);
        entry$min_fwd_pkt_len = fwd_size_stats["min"];
        entry$max_fwd_pkt_len = fwd_size_stats["max"];
        entry$mean_fwd_pkt_len = fwd_size_stats["mean"];
        entry$median_fwd_pkt_len = fwd_size_stats["median"];
        entry$mad_fwd_pkt_len = fwd_size_stats["mad"];
        entry$std_fwd_pkt_len = fwd_size_stats["std"];
        entry$skew_fwd_pkt_len = fwd_size_stats["skew"];
        entry$kurt_fwd_pkt_len = fwd_size_stats["kurt"];
        # entry$fwd_pkt_len_info = fwd_pkt_lengths[id];
    }

    if (id in bwd_pkt_lengths && |bwd_pkt_lengths[id]| > 0) {
        local bwd_size_stats = compute_len_stats(bwd_pkt_lengths[id]);
        entry$min_bwd_pkt_len = bwd_size_stats["min"];
        entry$max_bwd_pkt_len = bwd_size_stats["max"];
        entry$mean_bwd_pkt_len = bwd_size_stats["mean"];
        entry$median_bwd_pkt_len = bwd_size_stats["median"];
        entry$mad_bwd_pkt_len = bwd_size_stats["mad"];
        entry$std_bwd_pkt_len = bwd_size_stats["std"];
        entry$skew_bwd_pkt_len = bwd_size_stats["skew"];
        entry$kurt_bwd_pkt_len = bwd_size_stats["kurt"];
        # entry$bwd_pkt_len_info = bwd_pkt_lengths[id];
    }

    if (id in intervals_fwd && |intervals_fwd[id]| > 0) {
        local fwd_intv_stats = compute_intv_stats(intervals_fwd[id]);
        entry$min_fwd_pkt_interval = fwd_intv_stats["min"] * 1sec;
        entry$max_fwd_pkt_interval = fwd_intv_stats["max"] * 1sec;
        entry$mean_fwd_pkt_interval = fwd_intv_stats["mean"] * 1sec;
        entry$median_fwd_pkt_interval = fwd_intv_stats["median"] * 1sec;
        entry$mad_fwd_pkt_interval = fwd_intv_stats["mad"] * 1sec;
        entry$std_fwd_pkt_interval = fwd_intv_stats["std"] * 1sec;
        entry$skew_fwd_pkt_interval = fwd_intv_stats["skew"];
        entry$kurt_fwd_pkt_interval = fwd_intv_stats["kurt"];
        # entry$fwd_interval_info = intervals_fwd[id];
    }

    if (id in intervals_bwd && |intervals_bwd[id]| > 0) {
        local bwd_intv_stats = compute_intv_stats(intervals_bwd[id]);
        entry$min_bwd_pkt_interval = bwd_intv_stats["min"] * 1sec;
        entry$max_bwd_pkt_interval = bwd_intv_stats["max"] * 1sec;
        entry$mean_bwd_pkt_interval = bwd_intv_stats["mean"] * 1sec;
        entry$median_bwd_pkt_interval = bwd_intv_stats["median"] * 1sec;
        entry$mad_bwd_pkt_interval = bwd_intv_stats["mad"] * 1sec;
        entry$std_bwd_pkt_interval = bwd_intv_stats["std"] * 1sec;
        entry$skew_bwd_pkt_interval = bwd_intv_stats["skew"];
        entry$kurt_bwd_pkt_interval = bwd_intv_stats["kurt"];
        # entry$bwd_interval_info = intervals_bwd[id];
    }

    if (id in fwd_psh_counts)
        entry$fwd_psh_count = fwd_psh_counts[id];
    if (id in bwd_psh_counts)
        entry$bwd_psh_count = bwd_psh_counts[id];

    # Forward Bitrate
    if (id in fwd_pkt_lengths && id in first_pkt_time_fwd && id in last_pkt_time_fwd) {
        local fwd_total_bytes = 0;
        for (i in fwd_pkt_lengths[id])
            fwd_total_bytes += fwd_pkt_lengths[id][i];

        local fwd_duration = last_pkt_time_fwd[id] - first_pkt_time_fwd[id];
        if (fwd_duration > 0sec)
            entry$fwd_bitrate = fwd_total_bytes * 8.0 / (fwd_duration  / 1sec) /1024;
    }
    # Backward Bitrate
    if (id in bwd_pkt_lengths && id in first_pkt_time_bwd && id in last_pkt_time_bwd) {
        local bwd_total_bytes = 0;
        for (i in bwd_pkt_lengths[id])
            bwd_total_bytes += bwd_pkt_lengths[id][i];

        local bwd_duration = last_pkt_time_bwd[id] - first_pkt_time_bwd[id];
        if (bwd_duration > 0sec)
            entry$bwd_bitrate = bwd_total_bytes * 8.0 / (bwd_duration / 1sec) /1024;
    }   

    Log::write(LOG_PacketStats, entry);
}
def level(score):
    lv = ""
    if score == 0:
        lv = "no"
    elif 0 < score < 3:
        lv = "low"
    elif 3 < score < 7:
        lv = "mid"
    elif score > 7:
        lv = "high"
    return lv


def convert_time(seconds):
    seconds = seconds % (24 * 3600)
    hour = seconds // 3600
    seconds %= 3600
    minutes = seconds // 60
    seconds %= 60
    return "%dh %dmin %dsec" % (hour, minutes, seconds)

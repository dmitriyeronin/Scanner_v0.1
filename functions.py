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
    hours = seconds // 3600
    seconds %= 3600
    minutes = seconds // 60
    seconds %= 60
    return "%dh %dmin %dsec" % (hours, minutes, seconds)

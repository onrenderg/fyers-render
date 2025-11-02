def tick_data_stream(interval_seconds, num_ticks=10, start_price=100.0):
    from datetime import datetime, timezone
    import time
    import random
    
    current_price = start_price
    ticks = []
    
    for _ in range(num_ticks):
        tick = {
            "time": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "price": str(round(current_price + current_price * 0.02 * (random.random() - 0.5) * 2, 2))
        }
        current_price = float(tick["price"])
        ticks.append(tick)
        time.sleep(interval_seconds)
    
    return ticks

# print(tick_data_stream(1, num_ticks=1))

ticks = None
def received_data():
    global ticks 
    ticks = tick_data_stream(1, num_ticks=1)

    import dateutil.parser
    import datetime
    from datetime import timedelta, date, datetime
    time_datetime = dateutil.parser.parse(ticks[0]['time'])
    timenow = time_datetime  + timedelta()
    timenow_dt = timenow.strftime("%m/%d/%Y %H:%M:%S")
    print(ticks, timenow_dt)

for i in range(30):
    received_data()



# Candle create 
# https://www.youtube.com/watch?v=o_RFdbAQJ3w&t=37s
# print(ticks)


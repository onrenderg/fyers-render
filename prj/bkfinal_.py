from datetime import datetime
import pandas as pd
import os, time, json
from pytz import timezone

def setup_logger():
    """Initialize and configure the logger with dynamic filename"""
    from loguru import logger
    
    ist = timezone('Asia/Kolkata')
    log_filename = datetime.now(ist).strftime('%b%d').lower() + ".log"
    # Add logger with dynamic filename
    logger.add(
        log_filename,
        rotation="5 MB",
        retention="10 days",
        level="INFO",
        format="{time:YYYY-MM-DD HH:mm:ss} [{level}] {message}"
    )
    return logger

# Initialize logger
logger = setup_logger()

def setup_data_dir():
    """Setup and verify data directory"""
    import os
    
    data_dir = '/var/lib/data/'
    # Path for saving and reading csvs
    if not os.path.exists(data_dir):
        print(f"Data dir {data_dir} dont exist")
    else:
        print(f"Data dir {data_dir} does exist")
    return data_dir

# Setup data directory
data_dir = setup_data_dir()



def setup_deques():
    """Initialize deques for ticks and candles in-memory database"""
    from collections import deque
    
    ## Ticks imdb
    TICK_DEQUE_MAXLEN = 50
    tick_deque = deque(maxlen=TICK_DEQUE_MAXLEN)
    
    ## Candles imdb for rendering purpose 
    CANDLES_DEQUE_MAXLEN = 20000  # 1day 5sec = 4500 now 2 days with today day data 
    base_candle_deque = deque(maxlen=CANDLES_DEQUE_MAXLEN)
    
    return tick_deque, base_candle_deque
# Initialize deques
tick_deque, base_candle_deque = setup_deques()


#  save ws (the current WebSocket connection) in a global/shared variable when the client first connects.
active_ws = None
## var for sending udpate and thread  handling 
# ws_client = None
# ws_thread = None




###########################

def load_api_credentials():
    """Load API credentials from credentials module"""
    import credentials as cr
    
    APP_ID       = cr.APP_ID
    APP_TYPE     = cr.APP_TYPE
    SECRET_KEY   = cr.SECRET_KEY
    FY_ID        = cr.FY_ID
    APP_ID_TYPE  = cr.APP_ID_TYPE
    TOTP_KEY     = cr.TOTP_KEY
    PIN          = cr.PIN
    REDIRECT_URI = cr.REDIRECT_URI
    
    client_id = f'{APP_ID}-{APP_TYPE}'
    
    return APP_ID, APP_TYPE, SECRET_KEY, FY_ID, APP_ID_TYPE, TOTP_KEY, PIN, REDIRECT_URI, client_id
# Load API credentials
APP_ID, APP_TYPE, SECRET_KEY, FY_ID, APP_ID_TYPE, TOTP_KEY, PIN, REDIRECT_URI, client_id = load_api_credentials()
# @2 use api cred in auth_token_g fn 
from fyers_apiv3 import fyersModel
def gen_auth_token():
    # Need credentials.py in  same folder 
    import requests, time, base64, struct, hmac
    from fyers_apiv3 import fyersModel
    from urllib.parse import urlparse, parse_qs 
    import pyotp
    from urllib import parse
    import sys

    # Get access token using the new authentication logic

    # API endpoints
    BASE_URL = "https://api-t2.fyers.in/vagator/v2"
    BASE_URL_2 = "https://api-t1.fyers.in/api/v3"
    URL_SEND_LOGIN_OTP = BASE_URL + "/send_login_otp"
    URL_VERIFY_TOTP = BASE_URL + "/verify_otp"
    URL_VERIFY_PIN = BASE_URL + "/verify_pin"
    URL_TOKEN = BASE_URL_2 + "/token"
    URL_VALIDATE_AUTH_CODE = BASE_URL_2 + "/validate-authcode"

    SUCCESS = 1
    ERROR = -1
    # mongo_window
    def wait_for_next_totp_window():
        """Wait until the next 30-second TOTP window starts with buffer"""
        now = time.time()
        window_size = 30
        remaining = window_size - (now % window_size)
        wait_time = remaining + 2  # Add 2-second buffer
        logger.info(f"Waiting {wait_time:.1f}s for fresh TOTP window")
        time.sleep(wait_time)

    def send_login_otp(fy_id, app_id):
        """Send login OTP with retries"""
        for attempt in range(3):
            try:
                result = requests.post(URL_SEND_LOGIN_OTP, 
                                     json={"fy_id": fy_id, "app_id": app_id},
                                     timeout=5)
                if result.status_code == 200:
                    return [SUCCESS, result.json()["request_key"]]
                logger.warning(f"OTP send failed (attempt {attempt+1}): {result.text}")
            except Exception as e:
                logger.error(f"Network error (attempt {attempt+1}): {str(e)}")
            time.sleep(1)
        return [ERROR, "Failed after 3 attempts"]

    def verify_totp(request_key, totp):
        """Verify TOTP with enhanced logger"""
        logger.info(f"Verifying TOTP with request_key: {request_key[:15]}...")
        try:
            result = requests.post(URL_VERIFY_TOTP,
                                 json={"request_key": request_key, "otp": totp},
                                 timeout=5)
            if result.status_code == 200:
                return [SUCCESS, result.json()["request_key"]]
            return [ERROR, f"HTTP {result.status_code}: {result.text}"]
        except Exception as e:
            return [ERROR, str(e)]

    def generate_totp(secret):
        """Generate TOTP aligned with server time"""
        try:
            # Generate TOTP for current and next window
            totp = pyotp.TOTP(secret)
            current = totp.now()
            next_otp = totp.at(time.time() + 30)
            return [SUCCESS, current, next_otp]
        except Exception as e:
            return [ERROR, str(e)]

    def verify_PIN(request_key, pin):
        """Verify PIN with timeout"""
        try:
            result = requests.post(URL_VERIFY_PIN,
                                 json={
                                     "request_key": request_key,
                                     "identity_type": "pin",
                                     "identifier": pin
                                 },
                                 timeout=5)
            if result.status_code == 200:
                return [SUCCESS, result.json()["data"]["access_token"]]
            return [ERROR, f"HTTP {result.status_code}: {result.text}"]
        except Exception as e:
            return [ERROR, str(e)]

    def token(fy_id, app_id, redirect_uri, app_type, access_token):
        """Get auth token with improved error handling"""
        try:
            result = requests.post(
                URL_TOKEN,
                json={
                    "fyers_id": fy_id,
                    "app_id": app_id,
                    "redirect_uri": redirect_uri,
                    "appType": app_type,
                    "code_challenge": "",
                    "state": "sample_state",
                    "scope": "",
                    "nonce": "",
                    "response_type": "code",
                    "create_cookie": True
                },
                headers={'Authorization': f'Bearer {access_token}'},
                timeout=5
            )
            if result.status_code == 308:
                auth_code = parse.parse_qs(parse.urlparse(result.json()["Url"]).query)['auth_code'][0]                
                return [SUCCESS, auth_code]
            return [ERROR, f"HTTP {result.status_code}: {result.text}"]
        except Exception as e:
            return [ERROR, str(e)]

    # Main authentication flow with window alignment
    for attempt in range(3):  # Total authentication attempts
        try:
            # Wait for fresh TOTP window before starting
            wait_for_next_totp_window()

            # Generate auth code URL
            session = fyersModel.SessionModel(
                client_id=client_id,
                secret_key=SECRET_KEY,
                redirect_uri=REDIRECT_URI,
                response_type='code',
                grant_type='authorization_code'
            )
            urlToActivate = session.generate_authcode()
            logger.info(f"Auth URL: {urlToActivate}")

            # Step 1 - Send login OTP
            send_otp_result = send_login_otp(FY_ID, APP_ID_TYPE)
            if send_otp_result[0] != SUCCESS:
                raise Exception(f"OTP send failed: {send_otp_result[1]}")

            # Step 2 - Generate TOTP (current and next)
            generate_result = generate_totp(TOTP_KEY)
            if generate_result[0] != SUCCESS:
                raise Exception(f"TOTP generation failed: {generate_result[1]}")
            current_totp, next_totp = generate_result[1], generate_result[2]

            # Step 3 - Verify TOTP with retries
            for totp_attempt in range(2):
                verify_result = verify_totp(send_otp_result[1], current_totp)
                if verify_result[0] == SUCCESS:
                    break
                # Try next TOTP if current fails
                verify_result = verify_totp(send_otp_result[1], next_totp)
                if verify_result[0] == SUCCESS:
                    break
                time.sleep(1)
            else:
                raise Exception("TOTP verification failed after 2 attempts")

            # Step 4 - Verify PIN
            verify_pin_result = verify_PIN(verify_result[1], PIN)
            if verify_pin_result[0] != SUCCESS:
                raise Exception(f"PIN verification failed: {verify_pin_result[1]}")

            # Step 5 - Get auth code
            token_result = token(
                FY_ID, APP_ID, REDIRECT_URI, APP_TYPE, verify_pin_result[1]
            )
            if token_result[0] != SUCCESS:
                raise Exception(f"Token failed: {token_result[1]}")

            # Step 6 - Final access token
            session.set_token(token_result[1])
            response = session.generate_token()
            if response['s'] == 'ERROR':
                raise Exception(f"Final token error: {response.get('message', 'Unknown error')}")

            access_token = response["access_token"]
            logger.info("Authentication successful")
            break  # Exit retry loop on success

        except Exception as e:
            logger.error(f"Authentication attempt {attempt+1} failed: {str(e)}")
            if attempt == 2:
                logger.critical("All authentication attempts failed")
                sys.exit(1)
            time.sleep(5)
    else:
        logger.critical("All authentication attempts failed")
        sys.exit(1)


        access_token = response["access_token"]
        print(access_token)

    return access_token

# @4. 
def get_hist(clientId,accessToken):
    """
    Fetches historical candle data from Fyers API and populates the candles_data deque.
    """
    global base_candle_deque
    fyers = fyersModel.FyersModel(client_id=clientId, is_async=False, token=accessToken, log_path="./")
    

    #@mongo1
    static_date = datetime(2025, 4, 2)
    # Format static date
    current_date = static_date.strftime("%Y-%m-%d")
    range_from = current_date
    range_to = current_date
    data = {
        "symbol": "NSE:NIFTY50-INDEX",
        "resolution": "5S",
        "date_format": "1",
        "range_from": range_from,
        "range_to": range_to,
        "cont_flag": "1"
    }

    res = fyers.history(data=data)

    if "candles" in res:
        # Each candle is a list of 6 elements (time, open, high, low, close, volume)
        # We only want the first five, so we slice each candle accordingly.
        candles_sliced = [candle[:5] for candle in res['candles']]
        df = pd.DataFrame(candles_sliced, columns=['time', 'open', 'high', 'low', 'close'])

        # Convert time to integer timestamps if needed.
        df["time"] = df["time"].astype(int)

        # Convert historical timestamps from IST to UTC by subtracting 5.5 hours (19800 seconds)
        df["time"] = df["time"] - 19800

        # Append to candles_data deque
        for candle in df.to_dict(orient="records"):
            base_candle_deque.append(candle)

        logger.info(f"Historical candles appended. Total count: {len(base_candle_deque)}")
    else:
        logger.error("Failed to fetch historical data.")


# @3 ## Util1
""" Take incoming tick replay or (ws_client ticks then also  save to tick_deque)   and update 
the 5sec candles deque base_candle_deque and also send 
the updated candles latest to  active sub ws 
"""
def update_base_candle_deque(incoming_tick):
    global base_candle_deque, active_ws

    # incoming_tick["exch_feed_time"] is IST‑based epoch
    utc_ts = int(incoming_tick["exch_feed_time"]) - 19800
    # bucket it on 5s
    bucket_time = utc_ts - (utc_ts % 5)

    price = incoming_tick["ltp"]
    if base_candle_deque and base_candle_deque[-1]['time'] == bucket_time:
        last = base_candle_deque[-1]
        last['high']  = max(last['high'], price)
        last['low']   = min(last['low'],  price)
        last['close'] = price
        updated = last
    else:
        new_candle = {
            'time':  bucket_time,
            'open':  price,
            'high':  price,
            'low':   price,
            'close': price
        }
        base_candle_deque.append(new_candle)
        updated = new_candle

    if active_ws:
        try:
            active_ws.send(json.dumps({'candle': updated}, default=str))
        except Exception as e:
            logger.error(f"Error sending to WebSocket: {e}")
            active_ws = None


# @3 
def replay_feed(interval=1.0, date=None):
    """
    Replays tick data from a CSV file at the specified interval.
    
    Args:
        interval: Time between ticks in seconds (default: 1.0)
        date: Date to replay in format 'mmdd' (e.g., 'apr3'). If None, uses current date.
    """
    global candles_data
    
    # Determine which date to use
    ist = timezone('Asia/Kolkata')
    if date is None:
        date = datetime.now(ist).strftime('%b%d').lower()
    
    # csv_filename = f'{date}.csv'
    csv_filename = 'apr03.csv'
    csv_path = os.path.join(data_dir, csv_filename)
    
    if not os.path.exists(csv_path):
        logger.error(f"CSV file not found: {csv_path}")
        return
    
    try:
        # Load the CSV file
        df = pd.read_csv(csv_path, names=['timestamp', 'price'])
        
        # Convert timestamp strings to datetime objects
        df['timestamp'] = pd.to_datetime(df['timestamp'])
        
        # Ensure price is numeric
        df['price'] = pd.to_numeric(df['price'], errors='coerce')
        
        # Drop rows with NaN values
        df = df.dropna()
        
        logger.info(f"Loaded {len(df)} ticks from {csv_path}")
        
        # Process each tick
        for index, row in df.iterrows():
            # Create a tick object similar to what would come from Fyers WebSocket
            # The CSV has datetime strings, so we need to convert to Unix timestamps
            tick = {
                "exch_feed_time": int(row['timestamp'].timestamp()),
                "ltp": float(row['price'])
            }
            
            # Update  base candle imDb with this tick
            # update_candles_data(tick)
            update_base_candle_deque(tick)

            # Sleep for the specified interval
            time.sleep(interval)
            
            # Log progress occasionally
            if index % 100 == 0:
                logger.info(f"Processed {index} ticks")
            
    except Exception as e:
        logger.error(f"Error replaying CSV: {e}")




# @Main 
# bk_replay_loop
def realtime_feed_main():
    # 1. 
    access_token = gen_auth_token()

    # 2. get_hist()
    # Fetch historical data before starting real-time updates and append to base_candle_deaque
    get_hist(client_id, access_token)

    # 3. replay_feed
    replay_feed()

    # 3. realtime_feed
    # ws_client_connect(access_token)



#   @Rendering 
from flask import Flask, render_template_string, send_from_directory
from flask_sock import Sock
# Declare vars for
## flask wserverappl  and sockserverappl 
app = Flask(__name__)
sock = Sock(app)

@sock.route("/ws")
def ws_endpoint(ws):
    """
    Sets this connection as the active WebSocket and keeps it open.
    The active connection will receive candle updates directly from update_candle_with_tick.
    """
    global active_ws
    active_ws = ws
    try:
        # Keep the connection open
        while True:
            ws.receive()  # This call blocks until a message is received (or connection is closed)
    except Exception as e:
        logger.error(f"WebSocket error: {e}")
    finally:
        if active_ws == ws:
            active_ws = None
# @ui
LW_CHART = """
<script>
   const chart = LightweightCharts.createChart(document.getElementById('chart'), {
    width: window.innerWidth,
    height: window.innerHeight,
    priceScale: { borderColor: '#cccccc' },
    timeScale: { 
        borderColor: '#cccccc', 
        timeVisible: true, 
        secondsVisible: true,
        tickMarkFormatter: (time) => {
            const utcDate = new Date(time * 1000); // Convert UNIX time to Date object (UTC)
            const istDate = new Date(utcDate.getTime() + (5.5 * 60 * 60 * 1000)); // Convert to IST
            return istDate.toLocaleTimeString('en-IN');
        }
    },
    localization: {
        timeFormatter: (time) => {
            const utcDate = new Date(time * 1000);
            const istDate = new Date(utcDate.getTime() + (5.5 * 60 * 60 * 1000)); 
            return istDate.toLocaleDateString('en-IN') + ' ' + istDate.toLocaleTimeString('en-IN');
        }
    }
});

   const candleSeries = chart.addCandlestickSeries();
   
</script>
"""



SET_DATA = """
<script>
  // First, fetch historical data
  fetch('/historic')
    .then(response => response.json())    // ← close this .then()
    .then(candles => {
      // Set the initial data
      candleSeries.setData(candles);
    })
    .catch(error => console.error('Error fetching historical data:', error));
</script>
"""




UPDATE_DATA = """
<script>
  // Then connect to WebSocket for real-time updates
  const ws = new WebSocket(
    (location.protocol === "https:" ? "wss://" : "ws://") +
    location.host + "/ws"
  );

  ws.onmessage = function(event) {
    const data = JSON.parse(event.data);
    if (data.candle) {
      // Receiving a candle directly from the server
      candleSeries.update(data.candle);
    }
  };

  ws.onerror = error => console.error('WebSocket error:', error);
</script>
"""



JS_BLOCK =  f"""
{LW_CHART}
{SET_DATA}
{UPDATE_DATA}
"""

@app.route("/")
def index():
    """Serves the frontend chart."""
    html = f"""
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Live NIFTY Tick Chart (IST)</title>
        <script src="https://cdn.jsdelivr.net/gh/parth-royale/cdn@main/lightweight-charts.standalone.production.js"></script>
        <style>
            #chart {{
                position: relative;
                height: 600px;
                width: 100%;
                background-color: #131722;
            }}
            
            .floating-rectangle {{
                position: absolute;
                top: 10px;
                right: 10px;
                width: 300px;
                height: 500px;
                background-color: rgba(0, 128, 255, 0.8);
                border: 2px solid #0056b3;
                border-radius: 4px;
                display: flex;
                flex-direction: column;
                color: white;
                font-family: Arial, sans-serif;
                font-size: 12px;
                cursor: grab;
                z-index: 1000;
            }}
            
            .log-section {{
                flex: 1;
                overflow-y: auto;
                padding: 10px;
                border-bottom: 1px solid rgba(255,255,255,0.2);
            }}
            
            #chartUpdateLog {{
                background-color: rgba(0,0,0,0.2);
            }}
            
            #tradeLog {{
                background-color: rgba(0,0,0,0.1);
            }}
            
            #profitLog {{
                background-color: rgba(0,0,0,0.05);
            }}
            
            .log-entry {{
                margin-bottom: 5px;
                word-wrap: break-word;
            }}
            
            .profit-positive {{
                color: #081ff2;
            }}
            
            .profit-negative {{
                color: #a5fb06;
            }}
            
            .order-buttons {{
                display: flex;
                gap: 10px;
                margin: 10px 0;
            }}
            
            .order-buttons button {{
                padding: 8px 15px;
                cursor: pointer;
                border: none;
                border-radius: 3px;
                color: white;
                font-weight: bold;
            }}
            
            #l {{
                background-color: #4CAF50;
            }}
            
            #s {{
                background-color: #f44336;
            }}
        </style>
    </head>
    <body>
        <h1>Live NIFTY Tick Chart (IST)</h1>
        
        <div class="order-buttons">
            <button id="l">Long</button>
            <button id="s">Short</button>
        </div>
        
        <div id="chart"></div>
        
        <div id="floatingRectangle" class="floating-rectangle">
            <div id="chartUpdateLog" class="log-section">Chart Updates</div>
            <div id="tradeLog" class="log-section">Trade Logs</div>
            <div id="profitLog" class="log-section">Overall Profit</div>
        </div>

        {JS_BLOCK}
        <script>
            // Trading variables
            let totalTrades = 0;
            let profitableTrades = 0;
            let totalProfit = 0;
            let longTrades = 0;
            let shortTrades = 0;
            let isLong = false;
            let isShort = false;
            
            let entryPrice = 0;
            let latestPrice = null; 
            let latestCandleTime = null;
            let activeTrade = null;

            // Helper functions
            function convertToIST(timestamp) {{
                // Make sure timestamp is a Date object
                if (!(timestamp instanceof Date)) {{
                    timestamp = new Date(timestamp);
                }}
                
                // Add 5 hours and 30 minutes (IST offset from UTC)
                return new Date(timestamp.getTime() + (5.5 * 60 * 60 * 1000));
            }}
            
            function formatTime(timestamp) {{
                // Convert to IST first
                const istTime = convertToIST(timestamp);
                
                return istTime.toLocaleString('en-IN', {{
                    hour: '2-digit', 
                    minute: '2-digit', 
                    second: '2-digit', 
                    hour12: false
                }});
            }}

            function calculateProfit(entryPrice, exitPrice, isLong) {{
                if (!entryPrice || !exitPrice) return "0.00";
                return (((isLong ? exitPrice - entryPrice : entryPrice - exitPrice) / entryPrice) * 100).toFixed(2);
            }}

            function logChartUpdate(message) {{
                document.getElementById('chartUpdateLog').innerHTML = `Chart Updates<br>${{message}}`;
            }}

            function logTrade(message) {{
                const tradeLog = document.getElementById('tradeLog');
                tradeLog.innerHTML += `<div class="log-entry" id="latest-trade">${{message}}</div>`;
                tradeLog.scrollTop = tradeLog.scrollHeight;
            }}

            function updateProfitLog() {{
                const profitPercentage = totalProfit.toFixed(2);
                const profitClass = profitPercentage >= 0 ? 'profit-positive' : 'profit-negative';

                document.getElementById('profitLog').innerHTML = `
                    Overall Profit<br>
                    <span class="${{profitClass}}">Total Profit: ${{profitPercentage}}%</span><br>
                    Total Trades: ${{totalTrades}}<br>
                    Profitable Trades: ${{profitableTrades}}<br>
                    Long Trades: ${{longTrades}}<br>
                    Short Trades: ${{shortTrades}}
                `;
            }}

            // Floating rectangle dragging functionality
            function initializeFloatingRectangle() {{
                const floatingRectangle = document.getElementById('floatingRectangle');
                let isDragging = false;
                let offsetX = 0;
                let offsetY = 0;

                const startDrag = (e) => {{
                    isDragging = true;
                    const rect = floatingRectangle.getBoundingClientRect();
                    const clientX = e.touches ? e.touches[0].clientX : e.clientX;
                    const clientY = e.touches ? e.touches[0].clientY : e.clientY;
                    offsetX = clientX - rect.left;
                    offsetY = clientY - rect.top;
                    floatingRectangle.style.cursor = 'grabbing';
                }};

                const onDrag = (e) => {{
                    if (!isDragging) return;
                    const clientX = e.touches ? e.touches[0].clientX : e.clientX;
                    const clientY = e.touches ? e.touches[0].clientY : e.clientY;
                    floatingRectangle.style.left = `${{clientX - offsetX}}px`;
                    floatingRectangle.style.top = `${{clientY - offsetY}}px`;
                }};

                const endDrag = () => {{
                    isDragging = false;
                    floatingRectangle.style.cursor = 'grab';
                }};

                floatingRectangle.addEventListener('mousedown', startDrag);
                floatingRectangle.addEventListener('touchstart', startDrag, {{ passive: false }});
                document.addEventListener('mousemove', onDrag);
                document.addEventListener('touchmove', onDrag, {{ passive: false }});
                document.addEventListener('mouseup', endDrag);
                document.addEventListener('touchend', endDrag);
            }}

            // Trading functions
            function executeLongTrade() {{
                if (!latestPrice || !latestCandleTime) {{
                    alert("No price data available. Please wait for the data to update.");
                    return;
                }}

                if (isLong) {{
                    // Closing a long position
                    const profit = parseFloat(calculateProfit(entryPrice, latestPrice, true));
                    logTrade(`Long Close: ${{profit}}%, Entry: $${{entryPrice.toFixed(2)}}, Exit: $${{latestPrice.toFixed(2)}}, Time: ${{formatTime(latestCandleTime)}}`);
                    totalTrades++;
                    totalProfit += profit;
                    if (profit > 0) profitableTrades++;
                    longTrades++;
                    activeTrade = null;
                    isLong = false;
                }} else {{
                    // Opening a long position
                    if (isShort) {{
                        // Close existing short position first
                        const profit = parseFloat(calculateProfit(entryPrice, latestPrice, false));
                        logTrade(`Short Close: ${{profit}}%, Entry: $${{entryPrice.toFixed(2)}}, Exit: $${{latestPrice.toFixed(2)}}, Time: ${{formatTime(latestCandleTime)}}`);
                        totalTrades++;
                        totalProfit += profit;
                        if (profit > 0) profitableTrades++;
                        shortTrades++;
                        isShort = false;
                    }}
                    
                    // Now open long position
                    entryPrice = latestPrice;
                    logTrade(`Long Entry: Price: $${{latestPrice.toFixed(2)}}, Time: ${{formatTime(latestCandleTime)}}`);
                    activeTrade = {{ type: 'Long', entryPrice: latestPrice }}; 
                    isLong = true;
                }}
                
                updateProfitLog();
            }}

            function executeShortTrade() {{
                if (!latestPrice || !latestCandleTime) {{
                    alert("No price data available. Please wait for the data to update.");
                    return;
                }}

                if (isShort) {{
                    // Closing a short position
                    const profit = parseFloat(calculateProfit(entryPrice, latestPrice, false));
                    logTrade(`Short Close: ${{profit}}%, Entry: $${{entryPrice.toFixed(2)}}, Exit: $${{latestPrice.toFixed(2)}}, Time: ${{formatTime(latestCandleTime)}}`);
                    totalTrades++;
                    totalProfit += profit;
                    if (profit > 0) profitableTrades++;
                    shortTrades++;
                    activeTrade = null;
                    isShort = false;
                }} else {{
                    // Opening a short position
                    if (isLong) {{
                        // Close existing long position first
                        const profit = parseFloat(calculateProfit(entryPrice, latestPrice, true));
                        logTrade(`Long Close: ${{profit}}%, Entry: $${{entryPrice.toFixed(2)}}, Exit: $${{latestPrice.toFixed(2)}}, Time: ${{formatTime(latestCandleTime)}}`);
                        totalTrades++;
                        totalProfit += profit;
                        if (profit > 0) profitableTrades++;
                        longTrades++;
                        isLong = false;
                    }}
                    
                    // Now open short position
                    entryPrice = latestPrice;
                    logTrade(`Short Entry: Price: $${{latestPrice.toFixed(2)}}, Time: ${{formatTime(latestCandleTime)}}`);
                    activeTrade = {{ type: 'Short', entryPrice: latestPrice }}; 
                    isShort = true;
                }}
                
                updateProfitLog();
            }}

            // Initialize
            initializeFloatingRectangle();
            
            // Setup button handlers
            document.getElementById('l').onclick = executeLongTrade;
            document.getElementById('s').onclick = executeShortTrade;
            
            // Add keyboard shortcuts
            document.addEventListener('keydown', function(event) {{
                if (event.ctrlKey && event.key === 'b') {{
                    event.preventDefault();
                    executeLongTrade();
                }} else if (event.ctrlKey && event.key === 'v') {{
                    event.preventDefault();
                    executeShortTrade();
                }}
            }});
            
            // Connect to WebSocket for realtime price updates
            const originalOnMessage = ws.onmessage;
            ws.onmessage = function(event) {{
                const data = JSON.parse(event.data);
                if (data.candle) {{
                    latestPrice = data.candle.close;
                    latestCandleTime = new Date(data.candle.time * 1000); // Store raw time in milliseconds
                    const timeFormatted = formatTime(latestCandleTime);
                    
                    logChartUpdate(`Price: $${{latestPrice.toFixed(2)}}, Time: ${{timeFormatted}}`);
                    
                    // Update real-time P&L if there's an active trade
                    if (activeTrade) {{
                        const profit = calculateProfit(
                            activeTrade.entryPrice, 
                            latestPrice, 
                            activeTrade.type === 'Long'
                        );
                        const profitClass = parseFloat(profit) >= 0 ? 'profit-positive' : 'profit-negative';
                        
                        // Find the latest trade entry and update it with real-time P&L
                        const latestEntry = document.getElementById('latest-trade');
                        if (latestEntry) {{
                            // Keep the original entry text (before any P&L info)
                            let baseText = latestEntry.innerHTML;
                            if (baseText.includes('<br>')) {{
                                baseText = baseText.split('<br>')[0];
                            }}
                            
                            latestEntry.innerHTML = `${{baseText}}<br><span class="${{profitClass}}">Real-Time P&L: ${{profit}}%</span>`;
                        }}
                    }}
                }}
                
                // Call the original handler to update the chart
                if (originalOnMessage) {{
                    originalOnMessage.call(ws, event);
                }}
            }};
        </script>
    </body>
    </html>
    """
    return render_template_string(html)


realtime_feed_main()

port = int(os.getenv('PORT', 80))
print('Listening on port %s' % (port))
app.run(debug=False, host="0.0.0.0", port=port)
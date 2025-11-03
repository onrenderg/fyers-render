from flask import Flask, render_template_string, send_from_directory
from flask_sock import Sock
import json
from datetime import datetime
from collections import deque
import pandas as pd
import threading
import os
import time
from pytz import timezone
from apscheduler.schedulers.background import BackgroundScheduler
from loguru import logger  # Import loguru's logger
from fyers_apiv3 import fyersModel




import credentials as cr

APP_ID       = cr.APP_ID
APP_TYPE     = cr.APP_TYPE
SECRET_KEY   = cr.SECRET_KEY
FY_ID        = cr.FY_ID
APP_ID_TYPE  = cr.APP_ID_TYPE
TOTP_KEY     = cr.TOTP_KEY
PIN          = cr.PIN
REDIRECT_URI = cr.REDIRECT_URI






###################################################### Flask Setup #######################################################
app = Flask(__name__)
sock = Sock(app)

###################################################### Global Data ########################################################
# Global deque to store tick data for processing
DEQUE_MAXLEN = 50
tick_data = deque(maxlen=DEQUE_MAXLEN)
candles_data = deque(maxlen=50000)  # Increased size to store more historical candles

# Global variables for managing the Fyers WebSocket thread and graceful shutdown.
ws_client = None  # Will hold the FyersDataSocket instance
ws_thread = None
# Global variable to store the active WebSocket connection
active_ws = None

###################################################### logger Configuration ###############################################
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

logger.info(f"Initial tick_data: {list(tick_data)}")


data_dir = '/var/lib/data'

# check if data_dir exists
if not os.path.exists(data_dir):
    print(f"Data directory {data_dir} does not exist.")
else:
    print(f"Data directory {data_dir} exists.")


def update_candles_data(tick):
    """
    Processes an incoming tick to update the 5-second candle.
    If the tick falls within the current 5-second bucket, the candle is updated;
    otherwise, a new candle is created.
    After updating, sends the updated candle to the active WebSocket if connected.
    """
    global candles_data, active_ws
    
    # Convert tick's exchange feed time to an integer timestamp
    tick_dt = datetime.utcfromtimestamp(tick["exch_feed_time"]).replace(microsecond=0)
    tick_timestamp = int(tick_dt.timestamp())
    # Determine the 5-second bucket
    candle_time = tick_timestamp - (tick_timestamp % 5)
    
    if candles_data and candles_data[-1]['time'] == candle_time:
        # Update the existing candle
        last_candle = candles_data[-1]
        last_candle['high'] = max(last_candle['high'], tick["ltp"])
        last_candle['low'] = min(last_candle['low'], tick["ltp"])
        last_candle['close'] = tick["ltp"]
        updated_candle = last_candle
    else:
        # Create a new candle for a new 5-second bucket
        new_candle = {
            'time': candle_time,
            'open': tick["ltp"],
            'high': tick["ltp"],
            'low': tick["ltp"],
            'close': tick["ltp"]
        }
        candles_data.append(new_candle)
        updated_candle = new_candle

    # Send the updated candle to the active WebSocket if connected
    if active_ws:
        try:
            active_ws.send(json.dumps({'candle': updated_candle}, default=str))
        except Exception as e:
            logger.error(f"Error sending to WebSocket: {e}")
            active_ws = None

###################################################### WebSocket Client Setup (Fyers) #######################################
## Util2 
def gen_auth_token():
    # Need credentials.py in  same folder 
    import requests, time, base64, struct, hmac
    from fyers_apiv3 import fyersModel
    from urllib.parse import urlparse, parse_qs 
    import pyotp
    from urllib import parse
    import sys

    # Get _ token using the new authentication logic

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



def get_hist(clientId,accessToken):
    """
    Fetches historical candle data from Fyers API and populates the candles_data deque.
    """
    global candles_data
    fyers = fyersModel.FyersModel(client_id=client_id, is_async=False, token=accessToken, log_path="./")
    
    current_date = datetime.now().strftime("%Y-%m-%d")
    # Calculate date range
    # range_from = (datetime.now() - timedelta(days=4)).strftime("%Y-%m-%d")
    # range_to = (datetime.now() - timedelta(days=4)).strftime("%Y-%m-%d")
    # range_to = datetime.now().strftime("%Y-%m-%d")
    range_from = "2025-04-02"
    range_to = "2025-04-02"

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
            candles_data.append(candle)

        logger.info(f"Historical candles appended. Total count: {len(candles_data)}")
    else:
        logger.error("Failed to fetch historical data.")


def bk_replay_loop(interval=1.0, date=None):
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
    
    csv_filename = f'{date}.csv'
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
            update_candles_data(tick)
            
            # Sleep for the specified interval
            time.sleep(interval)
            
            # Log progress occasionally
            if index % 100 == 0:
                logger.info(f"Processed {index} ticks")
            
    except Exception as e:
        logger.error(f"Error replaying CSV: {e}")



client_id = f'{APP_ID}-{APP_TYPE}'

def realtime_feed_main():
    # 1. 
    access_token = gen_auth_token()

    # 2. get_hist()
    # Fetch historical data before starting real-time updates and append to base_candle_deaque
    get_hist(client_id, access_token)

    # 3. realtime_feed 
    # Start the replay with a specific date (e.g., 'apr3') or use None for today
    bk_replay_loop(interval=0.1, date='apr03')  # Replay at 10x speed @mongo2



###################################################### Flask WebSocket Server #######################################################
@sock.route("/ws")
def ws_endpoint(ws):
    """
    Sets this connection as the active WebSocket and keeps it open.
    The active connection will receive candle updates directly from update_candles_data.
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


###################################################### Flask Routes #######################################################
@app.route("/historic")
def get_historic_candles():
    """
    Returns all historical candles stored in memory.
    This endpoint is called when the chart is first loaded or refreshed.
    """
    return json.dumps(list(candles_data), default=str)

@app.route("/")
def index():
    """Serves the frontend chart."""
    html = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Live NIFTY Tick Chart (IST)</title>
    <script src="https://cdn.jsdelivr.net/gh/parth-royale/cdn@main/lightweight-charts.standalone.production.js"></script>
    <style>
        .timeframe-container {
            margin: 10px 0;
            text-align: center;
        }
        .tf-button {
            padding: 5px 10px;
            margin: 2px;
            cursor: pointer;
            border: 1px solid #ccc;
            background-color: #f8f8f8;
            border-radius: 3px;
        }
        .active {
            background-color: #4CAF50;
            color: white;
        }
    </style>
</head>
<body>
    <h1>Live NIFTY Tick Chart (IST)</h1>
    
    <div class="timeframe-container">
        <!-- Buttons for second-based timeframes -->
        <button class="tf-button active" data-timeframe="5s">5 Second</button>
        <button class="tf-button" data-timeframe="10s">10 Second</button>
        <button class="tf-button" data-timeframe="15s">15 Second</button>
        <button class="tf-button" data-timeframe="30s">30 Second</button>
        <button class="tf-button" data-timeframe="45s">45 Second</button>

        <!-- Buttons for minute-based timeframes -->
        <button class="tf-button" data-timeframe="1">1 Minute</button>
        <button class="tf-button" data-timeframe="3">3 Minute</button>
        <button class="tf-button" data-timeframe="5">5 Minute</button>
        <button class="tf-button" data-timeframe="10">10 Minute</button>
        <button class="tf-button" data-timeframe="15">15 Minute</button>
        <button class="tf-button" data-timeframe="30">30 Minute</button>
        <button class="tf-button" data-timeframe="60">1 Hour</button>
        
        <!-- Buttons for extended timeframes -->
        <button class="tf-button" data-timeframe="2h">2 Hour</button>
        <button class="tf-button" data-timeframe="4h">4 Hour</button>
        <button class="tf-button" data-timeframe="1d">1 Day</button>
        <button class="tf-button" data-timeframe="1w">1 Week</button>
        <button class="tf-button" data-timeframe="1month">1 Month</button>
    </div>
    
    <div id="chart"></div>
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

// Store original data
let originalData = [];
let currentTimeframe = '5s';

// Convert timeframe string to seconds (not milliseconds)
function getTimeframeMs(timeframe) {
    if (timeframe.endsWith('s')) {
        return parseInt(timeframe) * 1000;
    } else if (timeframe.endsWith('h')) {
        return parseInt(timeframe) * 60 * 60 * 1000;
    } else if (timeframe === '1d') {
        return 24 * 60 * 60 * 1000;
    } else if (timeframe === '1w') {
        return 7 * 24 * 60 * 60 * 1000;
    } else if (timeframe === '1month') {
        return 30 * 24 * 60 * 60 * 1000;
    } else {
        // Default to minutes
        return parseInt(timeframe) * 60 * 1000;
    }
}

// Resample data into bars for the given timeframe
function resampleData(data, timeframe) {
  const resampledData = [];
  let currentBar = null;
    const timeframeMs = getTimeframeMs(timeframe);
    const timeframeSec = timeframeMs / 1000; // Convert to seconds since data is in Unix seconds

  for (const row of data) {
    const barTime = Math.floor(row.time / timeframeSec) * timeframeSec;
    if (!currentBar || currentBar.time !== barTime) {
      if (currentBar) {
        resampledData.push(currentBar);
      }
      currentBar = {
        time: barTime,
        open: row.open,
        high: row.high,
        low: row.low,
        close: row.close,
        volume: row.volume
      };
    } else {
      currentBar.high = Math.max(currentBar.high, row.high);
      currentBar.low = Math.min(currentBar.low, row.low);
      currentBar.close = row.close;
      currentBar.volume += row.volume;
    }
  }
  if (currentBar) {
    resampledData.push(currentBar);
  }
  return resampledData;
}

// Update chart with resampled data
function updateChartTimeframe(timeframe) {
    currentTimeframe = timeframe;
    const resampledData = resampleData(originalData, timeframe);
    candleSeries.setData(resampledData);
}

// Set up timeframe button click handlers
document.querySelectorAll('.tf-button').forEach(button => {
    button.addEventListener('click', function() {
        // Remove active class from all buttons
        document.querySelectorAll('.tf-button').forEach(btn => {
            btn.classList.remove('active');
        });
        
        // Add active class to clicked button
        this.classList.add('active');
        
        // Update chart with selected timeframe
        updateChartTimeframe(this.getAttribute('data-timeframe'));
    });
});

// First, fetch historical data
fetch('/historic')
 .then(response => response.json())
 .then(candles => {
   // Store the original data
   originalData = candles;
   
   // Set the initial data with default timeframe
   updateChartTimeframe(currentTimeframe);
   
   // Then connect to WebSocket for real-time updates
   const ws = new WebSocket((location.protocol === "https:" ? "wss://" : "ws://") + location.host + "/ws");
   
   ws.onmessage = function(event) {
       const data = JSON.parse(event.data);
       if (data.candle) {
           // Add new candle to original data
           originalData.push(data.candle);
           
           // Update chart with resampled data including the new candle
           updateChartTimeframe(currentTimeframe);
       }
   };
 })
 .catch(error => {
   console.error('Error fetching historical data:', error);
 });
</script>
</body>
</html>
    """
    return render_template_string(html)


    
###################################################### Main Flow #######################################################
def main():
    """Starts the WebSocket client thread."""
    # create_table_if_not_exists()
    # Start ws_client_connect in a separate thread.
    global ws_thread
    ws_thread = threading.Thread(target=realtime_feed_main, daemon=True)
    ws_thread.start()
    logger.info("Fyers WebSocket thread started.")



main()



port = int(os.getenv('PORT', 80))
print('Listening on port %s' % (port))
app.run(debug=False, host="0.0.0.0", port=port)
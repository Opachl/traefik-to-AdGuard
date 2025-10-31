from traefiktoadguard import app
import schedule
import time

app.sync()
schedule.every(5).minutes.do(app.sync)

# Keep the script running indefinitely
while True:
    schedule.run_pending()
    time.sleep(1)

#!/usr/bin/env python3

import argparse
import requests
from time import strftime, sleep
from bs4 import BeautifulSoup
from loguru import logger
from twilio.rest import Client

# Set up logging to file
logger.add("oilpricelogging.log", format="{time} {level} {message}", level="INFO")

def send_message(client, to_number, from_number, text):
    try:
        message = client.messages.create(
            to=to_number,  # Your phone number
            from_=from_number,  # Twilio number
            body=text
        )
        logger.info(f"Message sent: {message.sid}")
    except Exception as e:
        logger.error(f"Failed to send message: {e}")

def price_check():
    url = "https://finance.yahoo.com/quote/CL%3DF/"
    headers = {"User-Agent": "Mozilla/5.0"}

    try:
        r = requests.get(url, headers=headers)
        logger.info(f"Requested {url} with status code {r.status_code}")
        if r.status_code == 200:
            soup = BeautifulSoup(r.text, "html.parser")
            # Find the price span using the appropriate class or attribute
            price_span = soup.find("fin-streamer", {"data-field": "regularMarketPrice"})
            if price_span:
                return price_span.text
            else:
                logger.error("Price not found")
                return "Price not found"
        else:
            logger.error(f"Failed to retrieve page. Status code: {r.status_code}")
            return "Failed to retrieve price"
    except Exception as e:
        logger.error(f"Error while scraping: {e}")
        return "error, request failed"

def main(args):
    # Set up Twilio client with credentials from argparse
    client = Client(args.account_sid, args.auth_token)
    
    while True:
        price = price_check()
        date = strftime("%m/%d/%y")
        clocktime = strftime("%I:%M %p")

        log_message = f"Crude oil price on {date} at {clocktime} is ${price}"
        logger.info(log_message)

        # Write to output file
        try:
            with open("oilprices.txt", "a") as f:
                f.write(f"{log_message}\n")
        except Exception as e:
            logger.error(f"Failed to write to file: {e}")

        # Send an SMS alert with price
        send_message(client, args.to_number, args.from_number, log_message)

        # Wait for 5 minutes before checking again
        sleep(300)

if __name__ == "__main__":
    # Argument parser for credentials and phone numbers
    parser = argparse.ArgumentParser(description="Crude Oil Price Tracker")
    parser.add_argument("account_sid", help="Your Twilio Account SID")
    parser.add_argument("auth_token", help="Your Twilio Auth Token")
    parser.add_argument("to_number", help="Your phone number to receive alerts")
    parser.add_argument("from_number", help="Your Twilio phone number to send alerts")

    # Parse the arguments
    args = parser.parse_args()

    try:
        main(args)
    except Exception as e:
        logger.critical(f"An unhandled exception occurred: {e}")

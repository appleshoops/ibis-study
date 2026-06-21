import yfinance as yf
import pandas as pd
import requests
from collections import OrderedDict

pd.set_option('display.max_columns', None)
pd.set_option('display.max_rows', None)

ticker = "AAPL"

stock = yf.Ticker(ticker)  # establishes ticker
sector_key = stock.info.get('sector')  # finds sector of ticker
if sector_key:
    sector_key = sector_key.lower().replace(" ", "-")  # sectors need to be lower case
sector_data = yf.Sector(sector_key)

# fetches the top ETFs in the sector and gets the ticker symbol of the first one
sector_etfs = sector_data.top_etfs
etf_symbol = next(iter(sector_etfs))

# gets another ticker for the etf
etf = yf.Ticker(etf_symbol)
etf_hist = etf.history(period="5y", interval="1d")  # get etf history

print(etf_hist)
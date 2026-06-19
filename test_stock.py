import yfinance as yf
import pandas as pd
import requests
from collections import OrderedDict

pd.set_option('display.max_columns', None)
pd.set_option('display.max_rows', None)

ticker = "AAPL"

url = f'https://www.alphavantage.co/query?function=NEWS_SENTIMENT&tickers={ticker}&apikey=8T0TGH76R6PPITIC&limit=3000'
r = requests.get(url)
data = r.json()

print(data)
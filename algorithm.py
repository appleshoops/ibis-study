import os
import joblib
import json
import textblob
import requests
import yfinance as yf
import pandas as pd
import yfCollectData
import numpy as np
import sqlite3
from polynomialWithWeightFinance import trainModel
from yfCollectData import volumeCollect, etfComparison, calcHighLowDiff, calcDailyReturns

def userStockBuyPrice(user_id, ticker_symbol):
    # get the ticker name and the price the user bought it at from the database
    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()
    cursor.execute("SELECT average_buy_price FROM Portfolio WHERE user_id = ? AND ticker = ?",
                   (user_id, ticker_symbol))
    user_stock = cursor.fetchone()
    conn.close()

    # check if user owns said stock
    if not user_stock:
        print(f'User does not own any {ticker_symbol} stock')
        return None

    return user_stock[0]

# run the prediction model
def stockProfit(ticker_symbol):
    features = [
        'Volume',
        '52 Week Range Position',
        'Top Sector ETF Close',
        'Daily Returns'
    ]

    # add the manual feature weights
    weight_Volume = 0.172
    weight_52_week_pos = 0.264
    weight_etf = 0.466
    weight_daily_returns = 0.097

    # set paths for the polynomial, model, and scaler
    poly_path = os.path.join("poly", f"{ticker_symbol}_poly_transformer_grades.pkl")
    model_path = os.path.join("models", f"{ticker_symbol}_polynomial_regression_model_grades.pkl")
    scaler_path = os.path.join("scaler", f"{ticker_symbol}_scaler_grades.pkl")

    # train the model for the given stock even if it exists already because there may be new data to train it on
    trainModel(ticker_symbol)
    print('ok model train yay')
    try:
        poly = joblib.load(poly_path)
        model = joblib.load(model_path)
        scaler = joblib.load(scaler_path)

        # gets current data for the given features from yfCollectData
        volume = volumeCollect(ticker_symbol)

        etf_hist = etfComparison(ticker_symbol)
        if etf_hist is None or etf_hist.empty:
            raise ValueError(f"Could not get ETF data for {ticker_symbol}")
        etf_current = etf_hist['Close'].iloc[-1]

        position_in_52w_range_hist = calcHighLowDiff(ticker_symbol)
        if position_in_52w_range_hist is None or position_in_52w_range_hist.empty:
            raise ValueError(f"Could not get 52-week range data for {ticker_symbol}")
        position_in_52w_range_current = position_in_52w_range_hist['position_in_52w_range'].iloc[-1]

        daily_returns_hist = calcDailyReturns(ticker_symbol)
        if daily_returns_hist is None or daily_returns_hist.empty:
            raise ValueError(f"Could not get daily returns for {ticker_symbol}")
        daily_returns_current = daily_returns_hist.iloc[-1]

        # puts current features into a dataframe for the model to read
        X_current = pd.DataFrame([{
            'Volume': volume,
            '52 Week Range Position': position_in_52w_range_current,
            'Top Sector ETF Close': etf_current,
            'Daily Returns': daily_returns_current
        }])

        X_current = X_current[features]

        X_current['Volume'] = X_current['Volume'] * weight_Volume
        X_current['52 Week Range Position'] = X_current['52 Week Range Position'] * weight_52_week_pos
        X_current['Top Sector ETF Close'] = X_current['Top Sector ETF Close'] * weight_etf
        X_current['Daily Returns'] = X_current['Daily Returns'] * weight_daily_returns

        X_scaled = scaler.transform(X_current)
        X_poly = poly.transform(X_scaled)

        # gets a prediction from the model and returns the predicted price as a float
        predicted_price = model.predict(X_poly)
        return float(predicted_price.ravel()[0])

    except Exception as e:
        print(e)
        return None

def getNewsSentiment(ticker_symbol):
    # try getting news sentiment from alphavantage api
    url = f'https://www.alphavantage.co/query?function=NEWS_SENTIMENT&tickers={ticker_symbol}&apikey=7VGY7S29TCWQEFB5&limit=1'
    try:
        newsJSON = requests.get(url).json()
        sentimentScore = newsJSON['feed'][0]['overall_sentiment_score'] # find sentiment score from JSON
    except KeyError as e: # if alphavantage hourly use is reached
        print('AlphaVantage API Ratelimit Reached')
        return None
    return sentimentScore

def getStockBeta(ticker_symbol):
    if not ticker_symbol or len(ticker_symbol.strip()) < 1:  # if ticker name is too short
        return None
    ticker = ticker_symbol.upper().strip()
    stock = yf.Ticker(ticker)
    stock_info = stock.info
    try:
        beta = stock_info.get('beta', None)  # get beta value from stock info, return None if not available
        print(f"Beta for {ticker_symbol}: {beta}")
        return beta
    except Exception as e:
        print(e)
        return None


def decisionTree(ticker_symbol, user_id, desired_change):
    predictedPrice = stockProfit(ticker_symbol)
    userStockPrice = userStockBuyPrice(user_id, ticker_symbol)
    percentageChange = ((predictedPrice - userStockPrice) / userStockPrice) * 100
    sentimentScore = getNewsSentiment(ticker_symbol)
    beta = getStockBeta(ticker_symbol)

    points = 0 # set points to 0 at the start of the decision tree

    # give points based on the predicted percentage change and the user's desired change
    if percentageChange >= desired_change:
        points += 10
        print(f"Predicted percentage change of {percentageChange:.2f}% meets or exceeds desired change of {desired_change}%, adding 10 points.")
    elif percentageChange < 0:
        points -= 10
        print(f"Predicted percentage change of {percentageChange:.2f}% is negative, subtracting 10 points.")

    # give points based on news headline sentiment score
    if sentimentScore:
        if sentimentScore <= -0.35:
            points -= 5
            print(f"Sentiment score of {sentimentScore} is very negative, subtracting 5 points.")
        elif -0.35 < sentimentScore <= -0.15:
            points -= 2
            print(f"Sentiment score of {sentimentScore} is negative, subtracting 2 points.")
        elif 0.15 < sentimentScore <= 0.35:
            points += 2
            print(f"Sentiment score of {sentimentScore} is positive, adding 2 points.")
        elif sentimentScore >= 0.35:
            points += 5
            print(f"Sentiment score of {sentimentScore} is very positive, adding 5 points.")
    else:
        print("Sentiment score not available, skipping sentiment analysis in decision tree.")

    if beta:
        if beta < 0.7:
            points += 2
            print(f"Beta of {beta} indicates lower volatility, adding 2 points.")
        elif beta < 1.0:
            points += 1
            print(f"Beta of {beta} indicates slightly lower volatility, adding 1 point.")
        elif beta > 1.3:
            points -= 2
            print(f"Beta of {beta} indicates higher volatility, subtracting 2 points.")
        elif beta > 1.0:
            points -= 1
            print(f"Beta of {beta} indicates slightly higher volatility, subtracting 1 point.")
    else:
        print("Beta value not available, skipping beta analysis in decision tree.")

    print(f'points is {points}')

decisionTree("AAPL", 6, 30)
import yfCollectData
import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import joblib

from sklearn.model_selection import train_test_split
from sklearn.preprocessing import PolynomialFeatures, StandardScaler
from sklearn.linear_model import LinearRegression, Ridge
from sklearn.metrics import mean_absolute_error, mean_squared_error, r2_score

from PolynomialWithWeight import X_train, use_ridge
from yfCollectData import stockDataCollection

plt.style.use('ggplot')

def trainModel(ticker_symbol):
    training_data = stockDataCollection(ticker_symbol) # gets training data from the yfCollectData subroutine

    X = training_data[['Volume', '52 Week Range Position', 'Top Sector ETF Close', 'Daily Returns']] # Sets features
    y = training_data[['Close']] # Sets what we're predicting to be the close value of the stock

    # setting test/train split to be 20%
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42
    )

    # setting the parameters of the training
    degree = 4 # highest power of the polynomial
    use_ridge = True # sets it to be a polynomial instead of linear regression
    ridge_alpha = 1.0

    # setting the weights of each feature, can be adjusted later
    weight_Volume = 1.0
    weight_52_week_pos = 1.0
    weight_etf = 1.0
    weight_daily_returns = 1.0

    # apply weights
    X_train_w = X_train.copy()
    X_test_w = X_test.copy()

    X_train_w['Volume'] = X_train_w['Volume'] * weight_Volume
    X_train_w['52 Week Range Position'] = X_train_w['52 Week Range Position'] * weight_52_week_pos
    X_train_w['Top Sector ETF Close'] = X_train_w['Top Sector ETF Close'] * weight_etf
    X_train_w['Daily Returns'] = X_train_w['Daily Returns'] * weight_daily_returns

    X_test_w['Volume'] = X_test_w['Volume'] * weight_Volume
    X_test_w['52 Week Range Position'] = X_test_w['52 Week Range Position'] * weight_52_week_pos
    X_test_w['Top Sector ETF Close'] = X_test_w['Top Sector ETF Close'] * weight_etf
    X_test_w['Daily Returns'] = X_test_w['Daily Returns'] * weight_daily_returns

    # polynomial features
    poly = PolynomialFeatures(degree=degree, include_bias=False)

    X_train_poly = poly.fit_transform(X_train_w)
    X_test_poly = poly.transform(X_test_w)

    print(f"Polynomial features shape: {X_train_poly.shape}")
trainModel("NVDA")
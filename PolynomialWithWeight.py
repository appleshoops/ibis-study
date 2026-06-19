import numpy as np
import pandas as pd
import matplotlib.pyplot as plt
plt.style.use('ggplot')
import joblib

from sklearn.model_selection import train_test_split
from sklearn.preprocessing import PolynomialFeatures, StandardScaler
from sklearn.linear_model import LinearRegression, Ridge
from sklearn.metrics import mean_absolute_error, mean_squared_error, r2_score

print("🔹 Step 1: Loading dataset...")
grades = pd.read_csv('../data/student-mat.csv', sep=';')

print("🔹 Step 2: Preparing data...")
grades = grades[['G3', 'absences', 'failures', 'G1', 'sex']].copy()
grades['sex_numeric'] = grades['sex'].map({'M': 0, 'F': 1})

# Features for modeling (sex only for coloring)
X = grades[['G1', 'absences', 'failures']]
y = grades['G3']

print(f"✅ Dataset shape: {grades.shape}")
print(f"Features used in model: {X.columns.tolist()}")

print("🔹 Step 3: Train/Test Split...")
X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.2, random_state=42
)

sex_test = grades.loc[X_test.index, 'sex_numeric']

# ==================== TUNABLE PARAMETERS ====================
degree = 3                    # ← Change this (2, 3, 4...)
use_ridge = True              # ← Set False to use normal LinearRegression
ridge_alpha = 1.0             # ← Higher = stronger regularization (try 0.1 to 10)

# Manual weighting to reduce dominance (e.g. lower failures influence)
weight_G1 = 1.0
weight_absences = 0.05
weight_failures = 0.03         # ← Lower this to reduce failures influence

# Apply weights
X_train_w = X_train.copy()
X_test_w = X_test.copy()

X_train_w['G1'] = X_train_w['G1'] * weight_G1
X_train_w['absences'] = X_train_w['absences'] * weight_absences
X_train_w['failures'] = X_train_w['failures'] * weight_failures

X_test_w['G1'] = X_test_w['G1'] * weight_G1
X_test_w['absences'] = X_test_w['absences'] * weight_absences
X_test_w['failures'] = X_test_w['failures'] * weight_failures

print(f"🔹 Step 4: Polynomial Features (degree={degree})...")
poly = PolynomialFeatures(degree=degree, include_bias=False)

X_train_poly = poly.fit_transform(X_train_w)
X_test_poly = poly.transform(X_test_w)

print(f"Polynomial features shape: {X_train_poly.shape}")

# ==================== TRAINING ====================
print("🔹 Step 5: Training model...")
if use_ridge:
    model = Ridge(alpha=ridge_alpha)
    print(f"   Using Ridge (alpha={ridge_alpha})")
else:
    model = LinearRegression()
    print("   Using Linear Regression")

model.fit(X_train_poly, y_train)
print("✅ Model training complete.")

# ==================== FEATURE IMPORTANCE ====================
print("\n🔹 Step 5.5: Feature Importance (%)")

feature_names = poly.get_feature_names_out()
coef_df = pd.DataFrame({
    'Feature': feature_names,
    'Abs_Coefficient': np.abs(model.coef_)
})

g1_terms = [f for f in feature_names if 'G1' in f]
absences_terms = [f for f in feature_names if 'absences' in f]
failures_terms = [f for f in feature_names if 'failures' in f]

g1_imp = coef_df[coef_df['Feature'].isin(g1_terms)]['Abs_Coefficient'].sum()
absences_imp = coef_df[coef_df['Feature'].isin(absences_terms)]['Abs_Coefficient'].sum()
failures_imp = coef_df[coef_df['Feature'].isin(failures_terms)]['Abs_Coefficient'].sum()

total = g1_imp + absences_imp + failures_imp

print("\n📊 Relative Feature Importance (%):")
print(f"   G1          : {(g1_imp/total*100):.1f}%")
print(f"   Absences    : {(absences_imp/total*100):.1f}%")
print(f"   Failures    : {(failures_imp/total*100):.1f}%")
print(f"   (Total: 100.0%)")

# ==================== EVALUATION & SAVE ====================
y_test_pred = model.predict(X_test_poly)

print(f"\nTest R²:    {r2_score(y_test, y_test_pred):.4f}")
print(f"Test MAE:   {mean_absolute_error(y_test, y_test_pred):.4f}")

joblib.dump(poly, 'poly_transformer_grades.pkl')
joblib.dump(model, 'polynomial_regression_model_grades.pkl')

# Plot
plt.figure(figsize=(10, 6))
plt.scatter(y_test, y_test_pred, c=sex_test, cmap='bwr', alpha=0.7, s=50)
plt.plot([y.min(), y.max()], [y.min(), y.max()], 'r--', lw=2)
plt.xlabel("Actual G3")
plt.ylabel("Predicted G3")
plt.title(f"Actual vs Predicted (degree={degree})")
plt.colorbar(label='Sex (0=Male, 1=Female)')
plt.grid(True)
plt.show()

print("🎉 Done!")
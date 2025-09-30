from typing import List
from src import URLFeatures
from src import init_db, log_prediction, get_prediction_by_url
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, HttpUrl
import uvicorn
import pickle
from pathlib import Path
from enum import Enum
import pandas as pd
from joblib import Parallel, delayed

class URLRequest(BaseModel):
    url: HttpUrl # validates URL syntax automatically

class URLBatchRequest(BaseModel):
    urls: List[HttpUrl] # validates URL syntax automatically

class pkl_path(Enum):
    column_transformer = Path.cwd() / "models" / "column_transformer.pkl"
    xgbc = Path.cwd() / "models" / "xgbc.pkl"

with open(pkl_path.column_transformer.value, 'rb') as file:
    column_transformer = pickle.load(file)

with open(pkl_path.xgbc.value, 'rb') as file:
    xgbc = pickle.load(file)

app = FastAPI()

# Initialize DB once at startup
init_db()

@app.post("/prediction")
async def prediction(request: URLRequest):
    try:
        url = str(request.url)
        cached_pred = get_prediction_by_url(url)
        if cached_pred is not None:
            return {"prediction": cached_pred}

        df = URLFeatures(url=url)
        X_norm = column_transformer.transform(df)
        xgbc_probs = xgbc.predict_proba(X_norm)[:, 1]
        xgbc_pred = (xgbc_probs > 0.713).astype(int)
        pred_value = xgbc_pred.tolist()[0]

        log_prediction(url, pred_value, df)

        return {"prediction": xgbc_pred.tolist()[0]}
    
    except HTTPException as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/batch-prediction")
async def batch_prediction(request: URLBatchRequest):
    try:
        urls = [str(url) for url in request.urls]
        predictions = []

        uncached_info = []
        for url in urls:
            cached_pred = get_prediction_by_url(url)
            if cached_pred is not None:
                predictions.append(cached_pred)
            else:
                uncached_info.append(url)

        if uncached_info:
            """
            backend:
                loky -> for multipricessing
                threading -> for multithreading
            """
            dfs = Parallel(n_jobs=-1, backend="threading")(
                delayed(URLFeatures)(url) for url in uncached_info
            )
            batch_df = pd.concat(dfs, ignore_index=True)
            X_norm = column_transformer.transform(batch_df)
            xgbc_probs = xgbc.predict_proba(X_norm)[:, 1]
            xgbc_pred = (xgbc_probs > 0.713).astype(int)

            # Log and append predictions
            for url, pred_value, df in zip(uncached_info, xgbc_pred.tolist(), dfs):
                log_prediction(url, pred_value, df)
                predictions.append(pred_value)

        return {"predictions": predictions}
    except HTTPException as e:
        raise HTTPException(status_code=500, detail=str(e))

    
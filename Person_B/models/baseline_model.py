"""PDF-aligned baseline: grouped CV, frozen holdout, leakage guards and reports."""
import json, sys
from pathlib import Path
import joblib, numpy as np, pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, average_precision_score, confusion_matrix, f1_score, precision_score, recall_score, roc_auc_score
from xgboost import XGBClassifier
ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path: sys.path.insert(0, str(ROOT))
from Person_B.models.splitting import assert_no_leakage, grouped_cv_splits, make_frozen_holdout
RESULTS_DIR = ROOT / "results"
MODEL_DIR = ROOT / "Person_B" / "models" / "saved"
DATA_PATH = ROOT / "data" / "processed" / "feature_table.csv"
METADATA_COLUMNS = {"package_id","package_name","group_id","version","analyzer_version","label"}
DIAGNOSTIC_COLUMNS = {"n_findings","parse_error_count","failed_static_analysis"}
SIZE_COLUMN = "n_py_files"

def get_feature_sets(df):
    excluded = METADATA_COLUMNS | DIAGNOSTIC_COLUMNS
    behavior = [c for c in df.columns if c not in excluded and c != SIZE_COLUMN]
    if not behavior: raise ValueError("No behavior features found.")
    if SIZE_COLUMN not in df: raise ValueError("n_py_files is required for size ablation.")
    return {"behavior_without_size": behavior, "behavior_with_size": behavior + [SIZE_COLUMN], "size_only": [SIZE_COLUMN]}

def make_models(y):
    positives, negatives = int((y == 1).sum()), int((y == 0).sum())
    scale = negatives / positives if positives else 1.0
    return {
      "random_forest": RandomForestClassifier(n_estimators=300,min_samples_leaf=2,class_weight="balanced",random_state=42,n_jobs=-1),
      "xgboost": XGBClassifier(n_estimators=200,max_depth=4,learning_rate=0.05,subsample=0.8,colsample_bytree=0.8,scale_pos_weight=scale,eval_metric="logloss",random_state=42,n_jobs=4)
    }

def score_predictions(y_true, probabilities, threshold=0.5):
    y_true=np.asarray(y_true,dtype=int); probabilities=np.asarray(probabilities,dtype=float)
    predicted=(probabilities>=threshold).astype(int)
    tn,fp,fn,tp=confusion_matrix(y_true,predicted,labels=[0,1]).ravel()
    return {"threshold":threshold,"accuracy":float(accuracy_score(y_true,predicted)),"precision":float(precision_score(y_true,predicted,zero_division=0)),"recall":float(recall_score(y_true,predicted,zero_division=0)),"f1":float(f1_score(y_true,predicted,zero_division=0)),"pr_auc":float(average_precision_score(y_true,probabilities)),"roc_auc":float(roc_auc_score(y_true,probabilities)),"tn":int(tn),"fp":int(fp),"fn":int(fn),"tp":int(tp),"fpr":float(fp/(fp+tn)) if fp+tn else 0.0}

def fit_checked(model,X,y):
    assert_no_leakage(list(X.columns))
    if X.columns.duplicated().any(): raise ValueError("Duplicate feature columns.")
    model.fit(X.astype(float).replace([np.inf,-np.inf],0).fillna(0),y.astype(int))
    return model

def run_baseline():
    if not DATA_PATH.exists(): raise FileNotFoundError(f"{DATA_PATH} missing; build the feature table first.")
    df=pd.read_csv(DATA_PATH)
    required={"package_id","group_id","label",SIZE_COLUMN}
    if not required.issubset(df.columns): raise ValueError(f"Missing columns: {sorted(required-set(df.columns))}")
    if df.package_id.duplicated().any(): raise ValueError("package_id must be unique.")
    if set(df.label.astype(int).unique())!={0,1}: raise ValueError("Dataset must contain both labels.")
    feature_sets=get_feature_sets(df)
    for cols in feature_sets.values(): assert_no_leakage(cols)
    development,holdout=make_frozen_holdout(df,n_splits=5,random_state=42)
    RESULTS_DIR.mkdir(parents=True,exist_ok=True); MODEL_DIR.mkdir(parents=True,exist_ok=True)
    holdout[["package_id","package_name","group_id","label"]].to_csv(RESULTS_DIR/"frozen_holdout_packages.csv",index=False)
    payload={"protocol":"5-fold StratifiedGroupKFold on development set plus frozen grouped holdout","positive_label":1,"group_column":"group_id","rows_total":int(len(df)),"groups_total":int(df.group_id.nunique()),"rows_development":int(len(development)),"rows_frozen_holdout":int(len(holdout)),"analyzer_version_note":"Not present in current source JSONL; kept null, not inferred.","experiments":{}}
    for experiment,columns in feature_sets.items():
      assert_no_leakage(columns); payload["experiments"][experiment]={}
      for model_name in ("random_forest","xgboost"):
        fold_scores=[]
        for train_idx,valid_idx in grouped_cv_splits(development,n_splits=5,random_state=42):
          train,valid=development.iloc[train_idx],development.iloc[valid_idx]
          model=make_models(train.label.astype(int))[model_name]
          fit_checked(model,train[columns],train.label)
          Xv=valid[columns].astype(float).replace([np.inf,-np.inf],0).fillna(0)
          fold_scores.append(score_predictions(valid.label,model.predict_proba(Xv)[:,1]))
        metric_names=[k for k in fold_scores[0] if k not in ("tn","fp","fn","tp")]
        cv={"mean_std":{k:{"mean":float(np.mean([s[k] for s in fold_scores])),"std":float(np.std([s[k] for s in fold_scores],ddof=1))} for k in metric_names},"confusion_counts_sum":{k:int(sum(s[k] for s in fold_scores)) for k in ("tn","fp","fn","tp")}}
        final=make_models(development.label.astype(int))[model_name]
        fit_checked(final,development[columns],development.label)
        Xh=holdout[columns].astype(float).replace([np.inf,-np.inf],0).fillna(0)
        hm=score_predictions(holdout.label,final.predict_proba(Xh)[:,1])
        model_path=MODEL_DIR/f"{model_name}_{experiment}.joblib"; joblib.dump(final,model_path)
        payload["experiments"][experiment][model_name]={"feature_count":len(columns),"features":columns,"cv_5fold":cv,"frozen_holdout":hm,"model_path":str(model_path.relative_to(ROOT))}
        print(f"{experiment} | {model_name}: PR-AUC={hm[chr(112)+chr(114)+chr(95)+chr(97)+chr(117)+chr(99)]:.4f} ROC-AUC={hm[chr(114)+chr(111)+chr(99)+chr(95)+chr(97)+chr(117)+chr(99)]:.4f} F1={hm[chr(102)+chr(49)]:.4f} FPR={hm[chr(102)+chr(112)+chr(114)]:.4f}")
    (RESULTS_DIR/"baseline_v1.json").write_text(json.dumps(payload,indent=2),encoding="utf-8")
    lines=["# SPIDER baseline v1","","Positive class: malicious (label 1). Holdout is not used for tuning.","","| Experiment | Model | PR-AUC | ROC-AUC | Precision | Recall | F1 | FPR | TN | FP | FN | TP |","|---|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|"]
    for exp,models in payload["experiments"].items():
      for name,result in models.items():
        m=result["frozen_holdout"]; lines.append(f"| {exp} | {name} | {m[chr(112)+chr(114)+chr(95)+chr(97)+chr(117)+chr(99)]:.4f} | {m[chr(114)+chr(111)+chr(99)+chr(95)+chr(97)+chr(117)+chr(99)]:.4f} | {m[chr(112)+chr(114)+chr(101)+chr(99)+chr(105)+chr(115)+chr(105)+chr(111)+chr(110)]:.4f} | {m[chr(114)+chr(101)+chr(99)+chr(97)+chr(108)+chr(108)]:.4f} | {m[chr(102)+chr(49)]:.4f} | {m[chr(102)+chr(112)+chr(114)]:.4f} | {m[chr(116)+chr(110)]} | {m[chr(102)+chr(112)]} | {m[chr(102)+chr(110)]} | {m[chr(116)+chr(112)]} |")
    lines += ["","Provenance notes: group_id is normalized package name; analyzer_version is null because the current source export does not provide it.","n_findings, parse-error count and failed-analysis status are diagnostics, excluded from model inputs.","Top-40 indicator vocabulary is selected by package-presence frequency without labels.","Benign labels are assumed-benign as documented in the shared dataset schema.",""]
    (RESULTS_DIR/"baseline_v1.md").write_text("\n".join(lines),encoding="utf-8")
    print("Saved results/baseline_v1.json and results/baseline_v1.md")

if __name__=="__main__": run_baseline()
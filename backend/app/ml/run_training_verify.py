"""Local training + inference verification script for Milestone 5."""
from backend.app.ml.train import train_models
from backend.app.ml.model_manager import get_state
from backend.app.ml.inference import run_inference
from backend.app.schemas.traffic import DirectionalFlowRecord
import pathlib

print("=" * 60)
print("MILESTONE 5 - LOCAL TRAINING")
print("=" * 60)
print("Starting local training (seed=42, 200 samples/class)...")
meta = train_models(seed=42, samples_per_class=200)

print()
print("=== TRAINING COMPLETE ===")
print(f"Model:              {meta.model_name} v{meta.model_version}")
print(f"Training samples:   {meta.training_sample_count}")
print(f"Classes:            {meta.classes}")
print(f"Class distribution: {meta.class_distribution}")
print(f"Random seed:        {meta.random_seed}")
print(f"Training source:    {meta.training_source}")
print(f"IF config:          {meta.isolation_forest_configuration}")
print()
if meta.validation_metrics:
    m = meta.validation_metrics
    print(f"Accuracy:           {m['accuracy']}")
    print(f"Macro Precision:    {m['macro_precision']}")
    print(f"Macro Recall:       {m['macro_recall']}")
    print(f"Macro F1:           {m['macro_f1']}")
    print(f"Weighted Precision: {m['weighted_precision']}")
    print(f"Weighted Recall:    {m['weighted_recall']}")
    print(f"Weighted F1:        {m['weighted_f1']}")
    print(f"Train samples:      {m['train_samples']}")
    print(f"Val samples:        {m['val_samples']}")
    print()
    print("Confusion matrix (rows=true, cols=predicted):")
    classes = meta.classes
    for i, row in enumerate(m["confusion_matrix"]):
        print(f"  {classes[i][:20]:20s}: {row}")
    print()
    print("Per-class metrics:")
    for cls, vals in m["per_class_metrics"].items():
        print(f"  {cls:20s}: P={vals['precision']:.4f}  R={vals['recall']:.4f}  F1={vals['f1']:.4f}")

print()
print("=" * 60)
print("MODEL ARTIFACTS")
print("=" * 60)
from backend.app.ml.model_manager import MODEL_DIR, CLASSIFIER_MODEL_FILE, ANOMALY_MODEL_FILE, METADATA_FILE
print(f"Classifier:     {CLASSIFIER_MODEL_FILE}  exists={CLASSIFIER_MODEL_FILE.is_file()}")
print(f"AnomalyDetect:  {ANOMALY_MODEL_FILE}  exists={ANOMALY_MODEL_FILE.is_file()}")
print(f"Metadata:       {METADATA_FILE}  exists={METADATA_FILE.is_file()}")
print(f"Readiness state: {get_state().value}")

print()
print("=" * 60)
print("REAL INFERENCE EXAMPLE")
print("=" * 60)

flow = DirectionalFlowRecord(
    flow_id="milestone5-verify-001",
    timestamp="2026-01-01T12:00:00Z",
    source_ip="10.0.0.55",
    source_port=45678,
    destination_ip="192.168.1.100",
    destination_port=443,
    protocol="TCP",
    duration=2.5,
    packet_count=20,
    byte_count=14400,
    packet_sizes=[720] * 20,
    packet_timestamps=[i * 0.125 for i in range(20)],
    inter_arrival_times=[0.125] * 19,
)

result = run_inference(flow)
print(f"Flow:                   {flow.flow_id}")
print(f"Protocol:               {flow.protocol}")
print()
print(f"threat_type:            {result.threat_type}")
print(f"classifier_confidence:  {result.classifier_confidence:.6f}")
print(f"anomaly_score:          {result.anomaly_score:.6f}")
print(f"is_anomaly:             {result.is_anomaly}")
print(f"model_version:          {result.model_version}")
print()
print("class_probabilities:")
for cls, prob in sorted(result.class_probabilities.items()):
    print(f"  {cls:22s}: {prob:.6f}")
print(f"  SUM = {sum(result.class_probabilities.values()):.6f}")
print()
print("feature_importances (all 16):")
for feat, imp in sorted(result.feature_importances.items(), key=lambda x: -x[1]):
    print(f"  {feat:35s}: {imp:.6f}")

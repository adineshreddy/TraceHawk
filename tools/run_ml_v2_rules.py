from prepare_ml_v2 import verify_prepared, OUTPUT, EXPERIMENT
from run_evaluation import main

if __name__ == "__main__":
    main(
        corpus=OUTPUT / "corpus",
        inputs=OUTPUT,
        report=EXPERIMENT / "rules.json",
        verify_fn=verify_prepared,
    )

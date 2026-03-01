#!/bin/bash
case "$1" in
  dataset) python data/prepare_dataset.py ;;
  train)   python model/train_model.py ;;
  api)     python api/app.py ;;
  test)    python tests/test_all.py ;;
  setup)   python data/prepare_dataset.py && python model/train_model.py && python tests/test_all.py ;;
  *)       echo "Usage: bash run.sh [dataset|train|api|test|setup]" ;;
esac

"""Phase 6 models and evaluation (see README "Models").

torch and LightGBM must not run in the same process: on macOS (arm64) each
loads its own OpenMP runtime (@rpath/libomp.dylib), and whichever is imported
second segfaults (tested 16 Nov, exit 139 both ways). LightGBM therefore runs
in a child process (ml/gbm_fit.py) that never imports torch.
"""

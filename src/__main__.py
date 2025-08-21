"""
Main entry point for ThreatInt CTI Pipeline
Supports both basic and enhanced modes
"""
import sys
import os
from pathlib import Path

def main():
    """Main entry point with mode selection"""
    # Ensure output directory exists
    Path('out').mkdir(exist_ok=True)
    
    # Check command line arguments for mode selection
    if len(sys.argv) > 1:
        mode = sys.argv[1].lower()
        
        if mode == 'basic':
            print("Running basic CTI pipeline...")
            from src.pipeline import run_once
            run_once(limit=20)
            
        elif mode == 'enhanced':
            print("Running enhanced CTI pipeline with ML and analytics...")
            from src.enhanced_pipeline import run_enhanced_pipeline_main
            run_enhanced_pipeline_main(limit=30)
            
        elif mode == 'benchmark':
            print("Running research benchmarks only...")
            from src.enhanced_pipeline import EnhancedThreatIntelligencePipeline
            pipeline = EnhancedThreatIntelligencePipeline()
            benchmark_path = pipeline.run_research_benchmarks()
            print(f"Benchmarks completed: {benchmark_path}")
            
        else:
            print(f"Unknown mode: {mode}")
            print_usage()
            
    else:
        # Default: run enhanced pipeline
        print("Running enhanced CTI pipeline (default mode)...")
        print("Use 'python -m src basic' for basic mode or 'python -m src benchmark' for benchmarks only")
        
        from src.enhanced_pipeline import run_enhanced_pipeline_main
        run_enhanced_pipeline_main(limit=25)

def print_usage():
    """Print usage information"""
    print("\nUsage: python -m src [mode]")
    print("Modes:")
    print("  basic     - Run basic CTI pipeline")
    print("  enhanced  - Run enhanced pipeline with ML and analytics (default)")
    print("  benchmark - Run research benchmarks only")
    print("\nExamples:")
    print("  python -m src")
    print("  python -m src enhanced")
    print("  python -m src basic")
    print("  python -m src benchmark")

if __name__ == "__main__":
    main()
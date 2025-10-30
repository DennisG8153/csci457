import os
import sys
import shutil
from typing import Dict, List, Optional, Tuple
from data_structures import ClassificationResult, StaticFeatures, LLMDescriptions, ArtemisTensor
from feature_extractor import unpack_apk, extract_static_features, extract_binary_features
from llm_tensor_builder import LLMDescriber, TensorBuilder
from model_report_generator import DualBranchCNN, render_report_html

def analyze_apk(
    apk_path: str,
    work_dir: str,
    cnn_weights_path: Optional[str] = None,
    llm_provider: Optional[str] = None,
    llm_model: Optional[str] = None,
    report_output: Optional[str] = None,
) -> Dict[str, object]:
    """
    Performs an end-to-end analysis of a single Android Application Package (APK) file.
    The process involves several stages: unpacking the APK, extracting static and binary
    features, generating semantic descriptions with an LLM, building tensors from these
    features, classifying the APK using a dual-branch CNN, and finally, generating an
    HTML report. A temporary working directory is used for intermediate files and is
    cleaned up after the analysis.

    Args:
        apk_path (str): The absolute path to the APK file to be analyzed.
        work_dir (str): A path to a directory for storing intermediate files (e.g., decompiled APK).
        cnn_weights_path (Optional[str]): Path to the pre-trained weights for the CNN model.
        llm_provider (Optional[str]): The LLM provider to use (e.g., "openai").
        llm_model (Optional[str]): The specific LLM model to use (e.g., "gpt-4o-mini").
        report_output (Optional[str]): The file path to save the generated HTML report.

    Returns:
        Dict[str, object]: A dictionary containing the analysis results, including
                           extracted features, LLM descriptions, classification result,
                           and the path to the report if generated.
    """
    # Step 1: Unpack the APK
    # Decompile the APK to a temporary directory to access its manifest, resources, and Smali code.
    unpacked_dir = os.path.join(work_dir, "decompiled_apk")
    if not unpack_apk(apk_path, unpacked_dir):
        print("APK unpacking failed. Aborting.")
        return {}

    # Step 2: Extract Features
    # Perform static analysis on the decompiled files and binary analysis on the original APK.
    print("Extracting static and binary features...")
    static = extract_static_features(unpacked_dir)
    binary = extract_binary_features(apk_path)
    
    # Step 3: Generate LLM Descriptions
    # Use an LLM to generate a natural language summary of potential risks based on static features.
    print("Generating LLM descriptions...")
    llm_describer = LLMDescriber(provider=llm_provider, model=llm_model)
    llm = llm_describer.describe(static)
    
    # Step 4: Build Tensors
    # Convert the extracted features and LLM descriptions into numerical tensors for the CNN.
    print("Building tensors for the model...")
    tensor_builder = TensorBuilder()
    tensors = tensor_builder.build(static, llm)
    
    # Step 5: Classify with CNN
    # Load the dual-branch CNN, optionally with pre-trained weights, and predict the APK's class.
    print("Classifying with the CNN model...")
    cnn_model = DualBranchCNN()
    if cnn_weights_path and os.path.exists(cnn_weights_path):
        cnn_model.load_weights(cnn_weights_path)
    result = cnn_model.predict_one(tensors)

    # Step 6: Generate Report
    # Create an HTML report summarizing the analysis if an output path is provided.
    saved_report = None
    if report_output:
        print(f"Generating HTML report at {report_output}...")
        saved_report = render_report_html(
            output_path=report_output,
            result=result,
            static=static,
            llm=llm,
        )

    # Step 7: Cleanup
    # Remove the temporary working directory.
    print(f"Cleaning up working directory: {work_dir}")
    shutil.rmtree(work_dir)

    print("Analysis complete.")
    return {
        "apk_path": apk_path,
        "static": static,
        "binary": binary,
        "llm_descriptions": llm,
        "classification": result,
        "report_path": saved_report,
    }

def _cli():
    """
    Defines and handles the command-line interface (CLI) for the APK analyzer.
    Uses argparse to parse command-line arguments and then calls the main `analyze_apk`
    function with the provided arguments.
    """
    import argparse
    p = argparse.ArgumentParser(description="Artemis APK Analyzer")
    p.add_argument("apk", help="Path to APK file")
    p.add_argument("--work", default="artemis_workdir", help="Working directory for decode & temp")
    p.add_argument("--weights", default=None, help="Path to CNN weights (.weights.h5 or .keras)")
    p.add_argument("--llm-provider", default=None, choices=[None, "openai", "hf"], help="LLM provider (optional)")
    p.add_argument("--llm-model", default=None, help="LLM model name for provider (optional)")
    p.add_argument("--report", default="artemis_report.html", help="Output HTML report path")
    args = p.parse_args()

    # Create the working directory if it doesn't exist.
    os.makedirs(args.work, exist_ok=True)

    analysis_result = analyze_apk(
        apk_path=args.apk,
        work_dir=args.work,
        cnn_weights_path=args.weights,
        llm_provider=args.llm_provider,
        llm_model=args.llm_model,
        report_output=args.report,
    )

    # Print the final classification result to the console.
    if analysis_result and "classification" in analysis_result:
        classification = analysis_result["classification"]
        print(f"\nFinal Classification: {classification.label} (Confidence: {classification.confidence:.2%})")

if __name__ == "__main__":
    _cli()
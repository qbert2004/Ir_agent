"""
Fine-tune LLM for Cybersecurity (CyberLLM)

This script fine-tunes an open-source LLM (Llama, Mistral, Phi)
on cybersecurity data using LoRA/QLoRA for efficient training.

Requirements:
    pip install transformers peft bitsandbytes accelerate datasets trl

Hardware Requirements:
    - LoRA: 8GB VRAM (RTX 3070/4070)
    - QLoRA (4-bit): 6GB VRAM
    - Full fine-tune: 24GB+ VRAM

Usage:
    python scripts/finetune_llm.py --model_name "microsoft/phi-2" --output_dir "./cyberllm"

    Or for larger model with QLoRA:
    python scripts/finetune_llm.py --model_name "mistralai/Mistral-7B-v0.1" --use_4bit
"""

import os
import json
import argparse
import logging
from typing import List, Dict, Any, Optional
from dataclasses import dataclass

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("finetune-llm")

# Check dependencies
try:
    import torch
    from transformers import (
        AutoModelForCausalLM,
        AutoTokenizer,
        TrainingArguments,
        BitsAndBytesConfig,
    )
    from peft import LoraConfig, get_peft_model, prepare_model_for_kbit_training
    from datasets import Dataset
    from trl import SFTTrainer
    DEPS_AVAILABLE = True
except ImportError as e:
    DEPS_AVAILABLE = False
    logger.error(f"Missing dependencies: {e}")
    logger.error("Install with: pip install transformers peft bitsandbytes accelerate datasets trl")


# ============================================================================
# DATA PREPARATION
# ============================================================================

def create_cybersecurity_dataset() -> List[Dict[str, str]]:
    """
    Create training dataset for cybersecurity fine-tuning.

    Format: instruction-response pairs for security analysis.
    """
    dataset = [
        # Event Classification
        {
            "instruction": "Classify this security event: Event ID 4688, Process: mimikatz.exe, CommandLine: mimikatz.exe sekurlsa::logonpasswords, User: SYSTEM",
            "response": """Classification: MALICIOUS (Critical)
Threat Type: Credential Theft
MITRE ATT&CK: T1003.001 - LSASS Memory

Analysis:
- mimikatz.exe is a well-known credential dumping tool
- sekurlsa::logonpasswords extracts plaintext passwords from LSASS memory
- Running as SYSTEM indicates privilege escalation succeeded

Recommended Actions:
1. Immediately isolate the affected system
2. Reset all credentials that may have been on this system
3. Check for lateral movement from this host
4. Preserve memory dump for forensic analysis"""
        },
        {
            "instruction": "Classify this security event: Event ID 4688, Process: notepad.exe, CommandLine: notepad.exe C:\\Users\\john\\document.txt, User: john",
            "response": """Classification: BENIGN
Threat Type: None
MITRE ATT&CK: N/A

Analysis:
- notepad.exe is a legitimate Windows application
- Opening a text file in user's home directory is normal activity
- Running under standard user context

Recommended Actions:
- No action required
- This is normal user activity"""
        },
        {
            "instruction": "Classify this security event: Event ID 4688, Process: powershell.exe, CommandLine: powershell.exe -enc SGVsbG8gV29ybGQ= -w hidden -ep bypass, User: john",
            "response": """Classification: MALICIOUS (High)
Threat Type: Suspicious Execution
MITRE ATT&CK: T1059.001 - PowerShell, T1027 - Obfuscated Files

Analysis:
- Base64 encoded command (-enc) hides the actual payload
- Hidden window (-w hidden) prevents user from seeing execution
- Execution policy bypass (-ep bypass) evades security controls
- Combination of these flags is highly suspicious

Recommended Actions:
1. Decode the base64 payload to understand the intent
2. Check for network connections from this process
3. Review parent process chain
4. Investigate user john's recent activity"""
        },

        # Incident Analysis
        {
            "instruction": "Analyze this ransomware incident timeline:\n1. 08:30 - User logon\n2. 08:35 - Outlook opened\n3. 08:37 - invoice.exe spawned from outlook.exe\n4. 08:38 - Connection to 185.220.101.45:443\n5. 08:40 - vssadmin delete shadows executed\n6. 08:45 - Mass file encryption detected",
            "response": """INCIDENT ANALYSIS: Ransomware Attack via Phishing

Attack Chain:
1. Initial Access (T1566.001): Phishing email with malicious attachment
2. Execution (T1204.002): User executed invoice.exe from email
3. C2 Communication (T1071.001): Established connection to C2 server
4. Defense Evasion (T1490): Deleted shadow copies to prevent recovery
5. Impact (T1486): Encrypted files for ransom

Indicators of Compromise:
- IP: 185.220.101.45 (C2 server)
- File: invoice.exe (malware)
- Process: outlook.exe -> invoice.exe (suspicious chain)

Root Cause: Phishing email bypassed email security

Remediation:
1. Isolate affected systems immediately
2. Block 185.220.101.45 at firewall
3. Preserve evidence before remediation
4. Check backups for restoration
5. Implement email sandboxing"""
        },

        # MITRE ATT&CK Mapping
        {
            "instruction": "Map this activity to MITRE ATT&CK: Process cmd.exe executed 'net user /domain' and 'nltest /dclist'",
            "response": """MITRE ATT&CK Mapping:

Tactic: Discovery (TA0007)

Techniques:
1. T1087.002 - Domain Account Discovery
   - 'net user /domain' enumerates domain user accounts
   - Used to identify targets for lateral movement

2. T1018 - Remote System Discovery
   - 'nltest /dclist' lists domain controllers
   - Attackers use this to identify high-value targets

Attacker Intent:
- Reconnaissance phase after initial access
- Gathering information for lateral movement
- Identifying privileged accounts and systems

Detection:
- Monitor for net.exe and nltest.exe executions
- Alert on domain enumeration from non-admin workstations
- Correlate with other suspicious activities"""
        },

        # IoC Analysis
        {
            "instruction": "Analyze these IoCs: IP 45.33.32.156, Domain evil-update.com, Hash: 5d41402abc4b2a76b9719d911017c592",
            "response": """IoC ANALYSIS:

1. IP Address: 45.33.32.156
   - Type: IPv4
   - Likely Role: Command & Control server
   - Action: Block at firewall, search logs for connections

2. Domain: evil-update.com
   - Type: Domain
   - Likely Role: Malware distribution or C2
   - Red Flags: 'evil' in name, 'update' used to appear legitimate
   - Action: Block at DNS, add to proxy blocklist

3. Hash: 5d41402abc4b2a76b9719d911017c592
   - Type: MD5 (32 characters)
   - Note: MD5 is weak, request SHA256 for better identification
   - Action: Search endpoints for file with this hash

Recommended Actions:
1. Add all IoCs to security tools (SIEM, EDR, Firewall)
2. Hunt for historical connections to IP/domain
3. Search for files matching the hash
4. Report to threat intelligence sharing platforms"""
        },

        # Threat Hunting
        {
            "instruction": "Create a threat hunting hypothesis for detecting lateral movement",
            "response": """THREAT HUNTING: Lateral Movement Detection

Hypothesis:
Attackers who have gained initial access are using legitimate remote access
tools (RDP, PsExec, WMI) to move laterally through the network.

Data Sources:
- Windows Security Event Logs (4624, 4648, 4672)
- Network flow data
- EDR telemetry

Hunt Queries:

1. Unusual RDP Logons (Event 4624, Logon Type 10):
   - Source: Non-IT workstations
   - Time: Outside business hours
   - Pattern: Sequential logons to multiple hosts

2. PsExec Artifacts:
   - Service installation: PSEXESVC
   - Named pipes: \\*\\PSEXESVC
   - Process: psexec.exe or psexesvc.exe

3. WMI Remote Execution:
   - Process: wmiprvse.exe spawning cmd/powershell
   - Network: WMI traffic (135/TCP, high ports)

Success Criteria:
- Identify compromised accounts used for lateral movement
- Map attacker's path through the network
- Find patient zero (initial compromised host)"""
        },

        # More training examples...
        {
            "instruction": "What is MITRE ATT&CK technique T1003?",
            "response": """MITRE ATT&CK T1003: OS Credential Dumping

Description:
Adversaries attempt to dump credentials from the operating system to obtain
account login information, typically in the form of hashes or clear text passwords.

Sub-techniques:
- T1003.001: LSASS Memory (mimikatz, procdump)
- T1003.002: Security Account Manager (SAM database)
- T1003.003: NTDS (Active Directory database)
- T1003.004: LSA Secrets
- T1003.005: Cached Domain Credentials
- T1003.006: DCSync
- T1003.007: Proc Filesystem
- T1003.008: /etc/passwd and /etc/shadow

Common Tools:
- Mimikatz
- Procdump
- Secretsdump
- DCSync (via mimikatz)

Detection:
- Monitor LSASS access (Event ID 4663, Sysmon 10)
- Watch for credential dumping tools
- Detect unusual SAM/NTDS access

Mitigation:
- Enable Credential Guard
- Limit debug privileges
- Use Protected Users security group"""
        },
        {
            "instruction": "Explain the difference between EDR and SIEM",
            "response": """EDR vs SIEM Comparison:

EDR (Endpoint Detection and Response):
- Focus: Individual endpoints (workstations, servers)
- Data: Process execution, file changes, network connections
- Capability: Real-time detection, automated response, forensics
- Examples: CrowdStrike, Carbon Black, Microsoft Defender ATP
- Strength: Deep endpoint visibility, automated containment

SIEM (Security Information and Event Management):
- Focus: Enterprise-wide log aggregation and correlation
- Data: Logs from all sources (endpoints, network, cloud, apps)
- Capability: Log correlation, alerting, compliance reporting
- Examples: Splunk, Microsoft Sentinel, Elastic SIEM
- Strength: Holistic view, correlation across systems

When to use:
- EDR: Endpoint-specific threats, malware, lateral movement
- SIEM: Multi-stage attacks, compliance, security operations

Best Practice: Use both - EDR feeds into SIEM for complete visibility"""
        },
    ]

    return dataset


def format_for_training(examples: List[Dict[str, str]], tokenizer) -> List[str]:
    """Format examples for instruction fine-tuning."""
    formatted = []

    for ex in examples:
        # Llama/Mistral chat format
        text = f"""<s>[INST] {ex['instruction']} [/INST] {ex['response']}</s>"""
        formatted.append(text)

    return formatted


def prepare_dataset(examples: List[Dict], tokenizer) -> Dataset:
    """Prepare HuggingFace dataset for training."""
    formatted = format_for_training(examples, tokenizer)
    return Dataset.from_dict({"text": formatted})


# ============================================================================
# MODEL SETUP
# ============================================================================

def setup_model_and_tokenizer(
    model_name: str,
    use_4bit: bool = False,
    use_8bit: bool = False
):
    """
    Setup model and tokenizer with optional quantization.

    Args:
        model_name: HuggingFace model name
        use_4bit: Use 4-bit quantization (QLoRA)
        use_8bit: Use 8-bit quantization

    Returns:
        model, tokenizer
    """
    logger.info(f"Loading model: {model_name}")

    # Quantization config
    bnb_config = None
    if use_4bit:
        bnb_config = BitsAndBytesConfig(
            load_in_4bit=True,
            bnb_4bit_quant_type="nf4",
            bnb_4bit_compute_dtype=torch.float16,
            bnb_4bit_use_double_quant=True,
        )
        logger.info("Using 4-bit quantization (QLoRA)")
    elif use_8bit:
        bnb_config = BitsAndBytesConfig(load_in_8bit=True)
        logger.info("Using 8-bit quantization")

    # Load model
    model = AutoModelForCausalLM.from_pretrained(
        model_name,
        quantization_config=bnb_config,
        device_map="auto",
        trust_remote_code=True,
        torch_dtype=torch.float16,
    )

    # Prepare for k-bit training if quantized
    if use_4bit or use_8bit:
        model = prepare_model_for_kbit_training(model)

    # Load tokenizer
    tokenizer = AutoTokenizer.from_pretrained(model_name, trust_remote_code=True)
    if tokenizer.pad_token is None:
        tokenizer.pad_token = tokenizer.eos_token

    return model, tokenizer


def setup_lora(model, r: int = 16, alpha: int = 32, dropout: float = 0.1):
    """
    Setup LoRA configuration and apply to model.

    Args:
        model: Base model
        r: LoRA rank (lower = fewer parameters, faster training)
        alpha: LoRA alpha (scaling factor)
        dropout: Dropout for LoRA layers

    Returns:
        PEFT model with LoRA
    """
    lora_config = LoraConfig(
        r=r,
        lora_alpha=alpha,
        lora_dropout=dropout,
        bias="none",
        task_type="CAUSAL_LM",
        target_modules=["q_proj", "k_proj", "v_proj", "o_proj"],  # Attention layers
    )

    model = get_peft_model(model, lora_config)

    # Print trainable parameters
    trainable_params = sum(p.numel() for p in model.parameters() if p.requires_grad)
    total_params = sum(p.numel() for p in model.parameters())
    logger.info(f"Trainable params: {trainable_params:,} ({100 * trainable_params / total_params:.2f}%)")

    return model


# ============================================================================
# TRAINING
# ============================================================================

def train(
    model,
    tokenizer,
    dataset,
    output_dir: str = "./cyberllm",
    epochs: int = 3,
    batch_size: int = 4,
    learning_rate: float = 2e-4,
    max_length: int = 1024,
):
    """
    Train the model using SFTTrainer.

    Args:
        model: Model to train
        tokenizer: Tokenizer
        dataset: Training dataset
        output_dir: Where to save the model
        epochs: Number of training epochs
        batch_size: Batch size (reduce if OOM)
        learning_rate: Learning rate
        max_length: Maximum sequence length
    """
    logger.info(f"Starting training for {epochs} epochs")

    training_args = TrainingArguments(
        output_dir=output_dir,
        num_train_epochs=epochs,
        per_device_train_batch_size=batch_size,
        gradient_accumulation_steps=4,
        learning_rate=learning_rate,
        weight_decay=0.01,
        warmup_ratio=0.1,
        logging_steps=10,
        save_steps=100,
        save_total_limit=2,
        fp16=True,
        optim="paged_adamw_8bit",
        lr_scheduler_type="cosine",
        report_to="none",  # or "tensorboard"
    )

    trainer = SFTTrainer(
        model=model,
        train_dataset=dataset,
        tokenizer=tokenizer,
        args=training_args,
        dataset_text_field="text",
        max_seq_length=max_length,
        packing=True,  # Pack multiple examples into one sequence
    )

    trainer.train()

    # Save final model
    trainer.save_model(output_dir)
    tokenizer.save_pretrained(output_dir)

    logger.info(f"Model saved to {output_dir}")


# ============================================================================
# INFERENCE
# ============================================================================

def inference(model, tokenizer, prompt: str, max_new_tokens: int = 512) -> str:
    """Generate response from fine-tuned model."""
    formatted_prompt = f"<s>[INST] {prompt} [/INST]"

    inputs = tokenizer(formatted_prompt, return_tensors="pt").to(model.device)

    with torch.no_grad():
        outputs = model.generate(
            **inputs,
            max_new_tokens=max_new_tokens,
            temperature=0.7,
            top_p=0.9,
            do_sample=True,
            pad_token_id=tokenizer.pad_token_id,
        )

    response = tokenizer.decode(outputs[0], skip_special_tokens=True)

    # Extract just the response part
    if "[/INST]" in response:
        response = response.split("[/INST]")[-1].strip()

    return response


# ============================================================================
# MAIN
# ============================================================================

def main():
    parser = argparse.ArgumentParser(description="Fine-tune LLM for Cybersecurity")
    parser.add_argument("--model_name", type=str, default="microsoft/phi-2",
                        help="Base model to fine-tune")
    parser.add_argument("--output_dir", type=str, default="./cyberllm",
                        help="Output directory for fine-tuned model")
    parser.add_argument("--use_4bit", action="store_true",
                        help="Use 4-bit quantization (QLoRA)")
    parser.add_argument("--use_8bit", action="store_true",
                        help="Use 8-bit quantization")
    parser.add_argument("--epochs", type=int, default=3,
                        help="Number of training epochs")
    parser.add_argument("--batch_size", type=int, default=4,
                        help="Batch size")
    parser.add_argument("--lora_r", type=int, default=16,
                        help="LoRA rank")
    parser.add_argument("--test_only", action="store_true",
                        help="Only test inference (no training)")
    args = parser.parse_args()

    if not DEPS_AVAILABLE:
        logger.error("Required dependencies not available. Exiting.")
        return

    print("=" * 70)
    print("CyberLLM Fine-tuning Script")
    print("=" * 70)
    print(f"Base Model: {args.model_name}")
    print(f"Output: {args.output_dir}")
    print(f"Quantization: {'4-bit' if args.use_4bit else '8-bit' if args.use_8bit else 'None'}")
    print("=" * 70)

    # Setup model
    model, tokenizer = setup_model_and_tokenizer(
        args.model_name,
        use_4bit=args.use_4bit,
        use_8bit=args.use_8bit
    )

    # Apply LoRA
    model = setup_lora(model, r=args.lora_r)

    if args.test_only:
        # Test inference
        print("\nTesting inference...")
        prompt = "Classify this security event: Event ID 4688, Process: mimikatz.exe, CommandLine: mimikatz sekurlsa::logonpasswords"
        response = inference(model, tokenizer, prompt)
        print(f"\nPrompt: {prompt}")
        print(f"\nResponse: {response}")
        return

    # Prepare dataset
    print("\nPreparing dataset...")
    examples = create_cybersecurity_dataset()
    print(f"Training examples: {len(examples)}")

    dataset = prepare_dataset(examples, tokenizer)

    # Train
    train(
        model=model,
        tokenizer=tokenizer,
        dataset=dataset,
        output_dir=args.output_dir,
        epochs=args.epochs,
        batch_size=args.batch_size,
    )

    print("\n" + "=" * 70)
    print("Fine-tuning complete!")
    print(f"Model saved to: {args.output_dir}")
    print("\nTo use the model:")
    print(f"  from transformers import AutoModelForCausalLM, AutoTokenizer")
    print(f"  model = AutoModelForCausalLM.from_pretrained('{args.output_dir}')")
    print(f"  tokenizer = AutoTokenizer.from_pretrained('{args.output_dir}')")
    print("=" * 70)


if __name__ == "__main__":
    main()

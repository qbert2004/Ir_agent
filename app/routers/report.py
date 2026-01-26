"""
Report Generation - С РЕАЛЬНЫМ AI АНАЛИЗОМ
Интегрирован с гибридной ML+Agent архитектурой
"""
import os
import logging
import httpx
from fastapi import APIRouter
from pydantic import BaseModel
from datetime import datetime
from groq import Groq

router = APIRouter(prefix="/api/report", tags=["Reports"])
logger = logging.getLogger("ir-agent")


class ReportRequest(BaseModel):
    time_range_hours: int = 24
    max_events: int = 100
    include_ai_analysis: bool = True


@router.post("/generate")
async def generate_report(request: ReportRequest):
    """
    Генерирует отчет с AI анализом гибридной обработки событий
    """
    try:
        logger.info(f"Generating report for last {request.time_range_hours} hours")

        # Получаем метрики через HTTP
        async with httpx.AsyncClient() as client:
            metrics_response = await client.get("http://localhost:9000/ingest/metrics")
            metrics_data = metrics_response.json()

            if metrics_data.get("status") != "success":
                return {
                    "status": "error",
                    "message": "Failed to fetch metrics"
                }

        logger.info(f"Metrics loaded: {metrics_data}")

        # Генерируем отчет с AI
        if request.include_ai_analysis:
            report_text = await _generate_ai_report(metrics_data, request.time_range_hours)
        else:
            report_text = _generate_basic_report(metrics_data, request.time_range_hours)

        # Формируем статистику
        processing = metrics_data.get("processing", {})
        paths = metrics_data.get("paths", {})
        betterstack = metrics_data.get("betterstack", {})

        return {
            "status": "success",
            "report": report_text,
            "generated_at": datetime.utcnow().isoformat(),
            "stats": {
                "total_events": processing.get("total_processed", 0),
                "malicious_detected": processing.get("malicious_detected", 0),
                "benign_filtered": processing.get("benign_filtered", 0),
                "fast_path": paths.get("fast_path_count", 0),
                "deep_path": paths.get("deep_path_count", 0),
                "agent_invocations": paths.get("agent_invocations", 0),
                "sent_to_betterstack": betterstack.get("sent", 0),
                "time_range_hours": request.time_range_hours
            }
        }

    except Exception as e:
        logger.error(f"Report generation error: {e}")
        import traceback
        traceback.print_exc()
        return {
            "status": "error",
            "message": str(e),
            "report": _generate_error_report(str(e))
        }


async def _generate_ai_report(metrics_data: dict, time_range_hours: int) -> str:
    """Генерирует отчет через Groq AI"""
    try:
        api_key = os.getenv("LLM_API_KEY")
        if not api_key:
            logger.warning("No Groq API key, using basic report")
            return _generate_basic_report(metrics_data, time_range_hours)

        logger.info("Calling Groq AI for report generation...")

        client = Groq(api_key=api_key)
        model = os.getenv("LLM_REPORT_MODEL", "llama-3.3-70b-versatile")

        # Извлекаем данные из новой структуры
        processing = metrics_data.get("processing", {})
        paths = metrics_data.get("paths", {})
        betterstack = metrics_data.get("betterstack", {})
        ml_model = metrics_data.get("ml_model", {})

        total = processing.get("total_processed", 0)
        malicious = processing.get("malicious_detected", 0)
        benign = processing.get("benign_filtered", 0)
        fast_path = paths.get("fast_path_count", 0)
        deep_path = paths.get("deep_path_count", 0)
        agent_calls = paths.get("agent_invocations", 0)
        sent = betterstack.get("sent", 0)
        failed = betterstack.get("failed", 0)

        prompt = f"""You are a security operations analyst. Generate a professional security incident report.

**Hybrid ML+Agent Processing Metrics (Last {time_range_hours} hours):**

**Event Processing:**
- Total Events Processed: {total}
- Malicious Detected: {malicious}
- Benign Filtered: {benign}
- Filter Rate: {processing.get('filter_rate', 'N/A')}

**Processing Paths:**
- Fast-Path (ML ≥80%): {fast_path} events
- Deep-Path (Agent Analysis): {deep_path} events
- Agent Invocations: {agent_calls}
- Deep-Path Rate: {paths.get('deep_path_rate', 'N/A')}

**Better Stack Forwarding:**
- Successfully Sent: {sent}
- Failed: {failed}

**ML Model:**
- Model Loaded: {ml_model.get('model_loaded', False)}
- F1 Score: {ml_model.get('metrics', {}).get('f1', 'N/A')}
- Accuracy: {ml_model.get('metrics', {}).get('accuracy', 'N/A')}

Generate a comprehensive Markdown report with:

## 1. Executive Summary
Brief overview of hybrid processing pipeline health and threat detection status.

## 2. Hybrid Processing Analysis
Analysis of Fast-Path vs Deep-Path distribution and Agent utilization.

## 3. Threat Detection Metrics
Table with detection statistics and their interpretation.

## 4. ML Model Performance
Assessment of ML model accuracy and effectiveness.

## 5. System Health Assessment
Overall health status (Excellent/Good/Warning/Critical) with explanation.

## 6. Recommendations
3-5 specific actionable recommendations for improvement.

Keep it professional, concise, and actionable. Use proper Markdown formatting."""

        logger.info(f"Sending request to Groq ({model})...")

        response = client.chat.completions.create(
            model=model,
            messages=[
                {
                    "role": "system",
                    "content": "You are a senior security operations analyst creating infrastructure reports. Be professional and actionable."
                },
                {
                    "role": "user",
                    "content": prompt
                }
            ],
            temperature=0.5,
            max_tokens=2000
        )

        ai_report = response.choices[0].message.content
        logger.info("AI report generated successfully")

        # Добавляем хедер с метриками
        report = f"""# Security Operations Report

**Generated:** {datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC")}
**Time Range:** Last {time_range_hours} hours
**Analysis Type:** AI-Powered (Groq {model})
**Architecture:** Hybrid ML + CyberAgent

---

{ai_report}

---

## Raw Metrics

### Event Processing
| Metric | Value |
|--------|-------|
| Total Processed | {total} |
| Malicious Detected | {malicious} |
| Benign Filtered | {benign} |
| Filter Rate | {processing.get('filter_rate', 'N/A')} |

### Processing Paths
| Path | Count | Description |
|------|-------|-------------|
| Fast-Path | {fast_path} | ML confidence ≥80% |
| Deep-Path | {deep_path} | Agent analysis (anomalous) |
| Agent Calls | {agent_calls} | Total Agent invocations |

### Better Stack
| Metric | Value |
|--------|-------|
| Sent | {sent} |
| Failed | {failed} |
| Status | {'Enabled' if betterstack.get('enabled') else 'Disabled'} |

---

*Report generated by IR-Agent with Groq AI - Hybrid ML+Agent Architecture*
"""

        return report

    except Exception as e:
        logger.error(f"AI report generation failed: {e}")
        import traceback
        traceback.print_exc()
        return _generate_basic_report(metrics_data, time_range_hours)


def _generate_basic_report(metrics_data: dict, time_range_hours: int) -> str:
    """Базовый отчет без AI"""
    processing = metrics_data.get("processing", {})
    paths = metrics_data.get("paths", {})
    betterstack = metrics_data.get("betterstack", {})
    ml_model = metrics_data.get("ml_model", {})

    total = processing.get("total_processed", 0)
    malicious = processing.get("malicious_detected", 0)
    benign = processing.get("benign_filtered", 0)
    fast_path = paths.get("fast_path_count", 0)
    deep_path = paths.get("deep_path_count", 0)
    sent = betterstack.get("sent", 0)

    # Calculate health
    if total > 0:
        detection_rate = (malicious / total) * 100
    else:
        detection_rate = 0

    report = f"""# Security Operations Report

**Generated:** {datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC")}
**Time Range:** Last {time_range_hours} hours
**Report Type:** Basic Summary (No AI)
**Architecture:** Hybrid ML + CyberAgent

---

## Executive Summary

Hybrid processing pipeline processed **{total} events** in the last {time_range_hours} hours.
- **{malicious}** events detected as malicious
- **{benign}** events filtered as benign
- **{sent}** events forwarded to Better Stack

## Processing Paths

| Path | Count | Description |
|------|-------|-------------|
| Fast-Path (ML) | {fast_path} | High confidence (≥80%), ~5ms |
| Deep-Path (Agent) | {deep_path} | Anomalous events, ~1-2s |

## Key Metrics

| Metric | Value |
|--------|-------|
| Total Events | {total} |
| Malicious Detected | {malicious} |
| Benign Filtered | {benign} |
| Filter Rate | {processing.get('filter_rate', 'N/A')} |
| Deep-Path Rate | {paths.get('deep_path_rate', 'N/A')} |
| Agent Invocations | {paths.get('agent_invocations', 0)} |

## ML Model

| Metric | Value |
|--------|-------|
| Status | {'Loaded' if ml_model.get('model_loaded') else 'Not Loaded'} |
| F1 Score | {ml_model.get('metrics', {}).get('f1', 'N/A'):.2%} |
| Accuracy | {ml_model.get('metrics', {}).get('accuracy', 'N/A'):.2%} |

## System Health

"""

    if detection_rate < 5:
        report += "✅ **Excellent** - Low threat activity, system operating normally.\n\n"
    elif detection_rate < 20:
        report += "✅ **Good** - Normal threat levels detected.\n\n"
    elif detection_rate < 50:
        report += "⚠️ **Warning** - Elevated threat activity detected.\n\n"
    else:
        report += "🚨 **Critical** - High threat activity requiring attention.\n\n"

    report += """## Recommendations

1. **Monitor Better Stack Dashboard**
   Review logs at: https://logs.betterstack.com

2. **Check Agent Invocations**
   If deep-path rate is high, review anomalous events

3. **Review ML Model Performance**
   Consider retraining if accuracy drops

4. **Enable AI Analysis**
   Configure Groq API key for deeper insights

---

*Basic report - Enable AI analysis for comprehensive insights*
"""

    return report


def _generate_error_report(error_msg: str) -> str:
    """Отчет об ошибке"""
    return f"""# Security Operations Report - Error

**Generated:** {datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC")}

## Status

❌ Unable to generate report due to error:

```
{error_msg}
```

## Troubleshooting Steps

1. Check API logs for errors
2. Verify Groq API key is configured
3. Ensure metrics endpoint is accessible: `GET /ingest/metrics`
4. Review application logs

## Support

- Better Stack Dashboard: https://logs.betterstack.com
- API Documentation: http://localhost:9000/docs
"""

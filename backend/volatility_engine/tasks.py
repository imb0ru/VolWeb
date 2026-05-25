from celery import shared_task
from evidences.models import Evidence
from yararules.models import YaraRule
from yararulesets.models import YaraRuleSet
from volatility_engine.engine import VolatilityEngine
from channels.layers import get_channel_layer
from asgiref.sync import async_to_sync
from yararules.utils import is_batch_upload_active
import logging

logger = logging.getLogger(__name__)

@shared_task(name="VolWeb.SelectiveEngine")
def start_selective_extraction(evidence_id, selected_plugins=None, pid_filter=None, skip_completed=False, plugin_timeout=None):
    """
    Extract artefacts using only the selected plugins.
    If skip_completed=True, skip plugins that already have successful results.
    If plugin_timeout is set, each individual plugin will be killed after that many seconds.
    """
    instance = Evidence.objects.get(id=evidence_id)
    engine = VolatilityEngine(instance)
    instance.status = 0
    instance.extraction_control = "running"
    instance.save()

    logger.info(f"Starting selective extraction for evidence {evidence_id} — plugins: {len(selected_plugins) if selected_plugins else 'all'}, timeout: {f'{plugin_timeout}s' if plugin_timeout else 'none'}")

    channel_layer = get_channel_layer()
    async_to_sync(channel_layer.group_send)(
        f"volatility_tasks_{evidence_id}",
        {
            "type": "send_notification",
            "message": {
                "name": "selective_extraction",
                "status": "started",
                "result": None,
            },
        },
    )

    try:
        engine.start_selective_extraction(selected_plugins, pid_filter, skip_completed=skip_completed, plugin_timeout=plugin_timeout)

        if instance.status != -1:
            instance.refresh_from_db()
            instance.status = 100
            instance.save(update_fields=["status"])
    finally:
        instance.refresh_from_db()
        instance.extraction_control = "idle"
        instance.celery_task_id = ""
        instance.save(update_fields=["extraction_control", "celery_task_id"])

    async_to_sync(channel_layer.group_send)(
        f"volatility_tasks_{evidence_id}",
        {
            "type": "send_notification",
            "message": {
                "name": "selective_extraction",
                "status": "finished",
                "result": str(instance.status != -1).lower(),
            },
        },
    )


@shared_task
def start_timeliner(evidence_id):
    """
    This task is dedicated to generate the timeline.
    We seperate this because this could take a very long time depending on the memory dump.
    """
    instance = Evidence.objects.get(id=evidence_id)
    channel_layer = get_channel_layer()
    engine = VolatilityEngine(instance)
    result = engine.start_timeliner()
    if result:
        async_to_sync(channel_layer.group_send)(
            f"volatility_tasks_{evidence_id}",
            {
                "type": "send_notification",
                "message": {
                    "name": "timeliner",
                    "status": "finished",
                    "result": "true",
                },
            },
        )
    else:
        async_to_sync(channel_layer.group_send)(
            f"volatility_tasks_{evidence_id}",
            {
                "type": "send_notification",
                "message": {
                    "name": "timeliner",
                    "status": "finished",
                    "result": "false",
                },
            },
        )


@shared_task
def dump_process(evidence_id, pid):
    """
    This task is dedicated to performing a pslist dump.
    """
    channel_layer = get_channel_layer()
    instance = Evidence.objects.get(id=evidence_id)
    engine = VolatilityEngine(instance)
    result = engine.dump_process(pid)
    async_to_sync(channel_layer.group_send)(
        f"volatility_tasks_{evidence_id}",
        {
            "type": "send_notification",
            "message": {
                "name": "dump",
                "pid": pid,
                "status": "finished",
                "result": result,
            },
        },
    )


@shared_task
def dump_windows_handles(evidence_id, pid):
    """
    This task is dedicated to compute the handles for a specific process.
    """
    instance = Evidence.objects.get(id=evidence_id)
    channel_layer = get_channel_layer()
    engine = VolatilityEngine(instance)
    engine.compute_handles(pid)
    async_to_sync(channel_layer.group_send)(
        f"volatility_tasks_{evidence_id}",
        {
            "type": "send_notification",
            "message": {
                "name": "handles",
                "pid": pid,
                "status": "finished",
                "msg": "Message",
            },
        },
    )


@shared_task
def dump_file(evidence_id, offset):
    """
    This task is dedicated for trying to dump a file at a specific memory offset.
    """
    instance = Evidence.objects.get(id=evidence_id)
    channel_layer = get_channel_layer()
    engine = VolatilityEngine(instance)
    if instance.os == "windows":
        result = engine.dump_file_windows(offset)
    else:
        result = engine.dump_file_linux(offset)
    async_to_sync(channel_layer.group_send)(
        f"volatility_tasks_{evidence_id}",
        {
            "type": "send_notification",
            "message": {
                "name": "file_dump",
                "status": "finished",
                "result": result,
            },
        },
    )


@shared_task
def dump_maps(evidence_id, pid):
    """
    This task is dedicated to compute the maps for a specific process.
    """
    instance = Evidence.objects.get(id=evidence_id)
    channel_layer = get_channel_layer()
    engine = VolatilityEngine(instance)
    result = engine.dump_process_maps(pid)
    async_to_sync(channel_layer.group_send)(
        f"volatility_tasks_{evidence_id}",
        {
            "type": "send_notification",
            "message": {
                "name": "maps",
                "pid": pid,
                "status": "finished",
                "result": result,
            },
        },
    )

@shared_task
def start_yararule_validation(yara_rule_id):
    """
    This task will validate the YARA rule and optionally trigger ruleset validation.
    
    Modified to respect batch upload context:
    - Individual rule validation always happens
    - Ruleset validation only happens if NOT in batch upload mode
    """
    instance = YaraRule.objects.get(id=yara_rule_id)
    
    logger.info(f"Starting validation for YARA rule: {instance.name} (ID: {yara_rule_id})")
    
    channel_layer = get_channel_layer()
    
    engine = VolatilityEngine(instance)
    
    # Set status to in-progress
    instance.status = 0
    instance.save()
    
    # Perform the actual validation
    engine.start_yararule_validation()
    instance.refresh_from_db()

    # Send individual rule validation notification
    from yararules.serializers import YaraRuleSerializer
    serializer = YaraRuleSerializer(instance)
    
    async_to_sync(channel_layer.group_send)(
        "yararules",
        {
            "type": "send_notification",
            "status": "created",  
            "message": serializer.data 
        }
    )
    logger.info(f"Completed validation for YARA rule: {instance.name}")


@shared_task
def start_ruleset_validation(yara_ruleset_id, skip_rule_validation=False):
    """
    Recompile a YARA ruleset.
    skip_rule_validation: skip per-rule revalidation (use after deletion —
                          remaining rules are already compiled).
    """
    instance = YaraRuleSet.objects.get(id=yara_ruleset_id)

    logger.info(f"Starting validation for YARA ruleset: {instance.name} (ID: {yara_ruleset_id})")

    channel_layer = get_channel_layer()

    engine = VolatilityEngine(instance)

    # Set status to in-progress
    instance.status = 0
    instance.save()

    # Perform the actual validation
    validation_result = engine.start_ruleset_validation(skip_rule_validation=skip_rule_validation)
    
    # Save the result
    instance.status = validation_result
    instance.save()
        
    from yararulesets.serializers import YaraRuleSetSerializer
    serializer = YaraRuleSetSerializer(instance)
    
    async_to_sync(channel_layer.group_send)(
        "yararulesets",
        {
            "type": "send_notification",
            "status": "updated",  # Status al livello principale!
            "message": serializer.data  # Dati serializzati
        }
    )
    logger.info(f"Completed validation for YARA ruleset: {instance.name} with status {instance.status}")


@shared_task
def start_yarascan(evidence_id, rulesets=None, rules=None, scan_scope="vad"):
    """
    Run YARA scan on evidence with selected rulesets and/or individual rules.

    Args:
        evidence_id: ID of the evidence to scan
        rulesets: List of ruleset IDs to use
        rules: List of individual rule IDs to use
        scan_scope: "vad" (per-process memory, default) or "kernel"
                    (kernel layer). Selects which Volatility plugin
                    drives the scan; see VolatilityEngine.run_yara_scan.
    """
    import traceback
    from datetime import datetime
    
    try:
        instance = Evidence.objects.get(id=evidence_id)
        channel_layer = get_channel_layer()
        engine = VolatilityEngine(instance)
        
        logger.info(f"Starting YARA scan for evidence {evidence_id} with rulesets: {rulesets}, rules: {rules}")
        
        # Send start notification
        async_to_sync(channel_layer.group_send)(
            f"volatility_tasks_{evidence_id}",
            {
                "type": "send_notification",
                "message": {
                    "name": "yarascan",
                    "status": "started",
                    "result": None,
                },
            },
        )
        
        # Initialize scan_executed to track if any scan was performed
        scan_executed = False
        scan_results = []
        
        # If specific rulesets are selected, combine them in a single scan
        if rulesets:
            from yararulesets.models import YaraRuleSet
            selected_rulesets = []
            
            for ruleset_id in rulesets:
                try:
                    # Try to fetch the ruleset regardless of its status. We will
                    # only include it in the scan if it has compiled rules.
                    ruleset = YaraRuleSet.objects.get(id=ruleset_id)

                    if getattr(ruleset, 'compiled_rules', None):
                        selected_rulesets.append(ruleset)
                        logger.info(f"Added ruleset '{ruleset.name}' to scan")
                    else:
                        logger.warning(f"Ruleset {ruleset_id} found but not compiled yet; skipping")
                except YaraRuleSet.DoesNotExist:
                    logger.warning(f"Ruleset {ruleset_id} not found")
            
            if selected_rulesets:
                logger.info(f"Running YARA scan with {len(selected_rulesets)} rulesets combined (scope={scan_scope})")
                scan_result = engine.run_yara_scan(yara_rulesets=selected_rulesets, scan_scope=scan_scope)
                
                # Mark that a scan was executed
                scan_executed = True
                
                # Collect results if any matches found
                if scan_result is not None and scan_result != []:
                    scan_results.extend(scan_result if isinstance(scan_result, list) else [scan_result])
                    
        # If specific rules are selected (without ruleset)
        elif rules:
            logger.info(f"Running YARA scan with individual rules: {rules} (scope={scan_scope})")

            scan_result = engine.run_yara_scan(yara_rules=rules, scan_scope=scan_scope)
            
            # Mark that a scan was executed
            scan_executed = True
            
            # Collect results if any matches found
            if scan_result is not None and scan_result != []:
                scan_results.extend(scan_result if isinstance(scan_result, list) else [scan_result])
                
        # If no specific selections, run with all active rules
        else:
            logger.info(f"Running YARA scan with all active rules (scope={scan_scope})")
            scan_result = engine.run_yara_scan(scan_scope=scan_scope)
            
            # Mark that a scan was executed
            scan_executed = True
            
            # Collect results if any matches found
            if scan_result is not None and scan_result != []:
                scan_results.extend(scan_result if isinstance(scan_result, list) else [scan_result])
        
        # Determine the result based on whether scan was executed successfully
        # A scan is successful if it was executed, regardless of whether matches were found
        result = scan_executed
        
        # Generate a unique scan ID with timestamp for logging
        scan_timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        scan_id = f"scan_{scan_timestamp}"
        
        logger.info(f"YARA scan completed for evidence {evidence_id}. Found {len(scan_results)} total matches. Scan ID: {scan_id}")
        
        # Send finished notification
        async_to_sync(channel_layer.group_send)(
            f"volatility_tasks_{evidence_id}",
            {
                "type": "send_notification",
                "message": {
                    "name": "yarascan",
                    "status": "finished",
                    "result": str(result).lower(),
                    "scan_id": scan_id,  # Include scan ID in notification
                    "matches_count": len(scan_results),  # Include match count
                },
            },
        )
        
    except Evidence.DoesNotExist:
        logger.error(f"Evidence with ID {evidence_id} not found")
        result = False
        
        # Send error notification
        async_to_sync(channel_layer.group_send)(
            f"volatility_tasks_{evidence_id}",
            {
                "type": "send_notification",
                "message": {
                    "name": "yarascan",
                    "status": "error",
                    "result": "false",
                    "error": "Evidence not found",
                },
            },
        )
        
    except Exception as e:
        logger.error(f"Error during YARA scan: {str(e)}")
        logger.error(traceback.format_exc())
        result = False
        
        # Send error notification
        async_to_sync(channel_layer.group_send)(
            f"volatility_tasks_{evidence_id}",
            {
                "type": "send_notification",
                "message": {
                    "name": "yarascan",
                    "status": "error",
                    "result": "false",
                    "error": str(e),
                },
            },
        )
        
    return result
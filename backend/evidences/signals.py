from django.db.models.signals import post_save, post_delete
from django.dispatch import receiver
from evidences.models import Evidence
from evidences.serializers import EvidenceSerializer
from asgiref.sync import async_to_sync
from channels.layers import get_channel_layer


@receiver(post_save, sender=Evidence)
def send_evidence_created(sender, instance, created, **kwargs):

    # Kick off automatic Linux ISF resolution so the analyst doesn't have to
    # upload kernel symbols manually before running plugins.
    if created and instance.os == "linux":
        try:
            from volatility_engine.tasks import generate_linux_symbols
            generate_linux_symbols.delay(instance.id)
        except Exception:
            import logging
            logging.getLogger(__name__).exception(
                "Failed to enqueue Linux ISF resolution for evidence %s", instance.id
            )

    channel_layer = get_channel_layer()
    serializer = EvidenceSerializer(instance)
        
    # Send to the general evidences group
    async_to_sync(channel_layer.group_send)(
        "evidences",
        {"type": "send_notification", "status": "created", "message": serializer.data},
    )
    
    # Also send to the case-specific group
    if instance.linked_case:
        async_to_sync(channel_layer.group_send)(
            f"evidences_case_{instance.linked_case.id}",
            {"type": "send_notification", "status": "created", "message": serializer.data},
        )


@receiver(post_delete, sender=Evidence)
def send_evidence_deleted(sender, instance, **kwargs):
    channel_layer = get_channel_layer()
    serializer = EvidenceSerializer(instance)
        
    # Send to the general evidences group
    async_to_sync(channel_layer.group_send)(
        "evidences",
        {"type": "send_notification", "status": "deleted", "message": serializer.data},
    )
    
    # Also send to the case-specific group
    if instance.linked_case:
        async_to_sync(channel_layer.group_send)(
            f"evidences_case_{instance.linked_case.id}",
            {"type": "send_notification", "status": "deleted", "message": serializer.data},
        )
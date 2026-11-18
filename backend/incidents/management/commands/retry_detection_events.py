from django.core.management.base import BaseCommand, CommandError

from incidents.detection.event_processor import retry_pending_detection_events


class Command(BaseCommand):
    help = "Retry pending detection events after a transient rule-processing failure."

    def add_arguments(self, parser):
        parser.add_argument("--limit", type=int, default=100)

    def handle(self, *args, **options):
        limit = options["limit"]
        if limit < 1:
            raise CommandError("--limit must be a positive integer.")

        result = retry_pending_detection_events(limit=limit)
        self.stdout.write(
            self.style.SUCCESS(
                f"Attempted {result['attempted']} pending event(s); "
                f"completed {result['completed']}."
            )
        )

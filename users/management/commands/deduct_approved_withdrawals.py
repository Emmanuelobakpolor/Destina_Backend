from django.core.management.base import BaseCommand
from django.db import transaction
from django.utils import timezone
from users.models import WithdrawalRequest, DriverProfile, User
from decimal import Decimal
import logging

logger = logging.getLogger(__name__)

class Command(BaseCommand):
    help = 'Deduct earnings for manually approved withdrawal requests that were not processed via API'

    def handle(self, *args, **options):
        # Find approved withdrawals where processed_at is null (indicating manual approval without API trigger)
        approved_withdrawals = WithdrawalRequest.objects.filter(
            status='approved',
            processed_at__isnull=True  # Target only those without API processing timestamp
        ).select_related('driver_profile__user')

        if not approved_withdrawals.exists():
            self.stdout.write(self.style.SUCCESS('No approved withdrawals needing deduction found.'))
            return

        total_deducted = Decimal('0.00')
        for withdrawal in approved_withdrawals:
            driver_user = withdrawal.driver_profile.user
            amount = withdrawal.amount

            if driver_user.todays_earnings < amount:
                logger.warning(f"Skipping deduction for {withdrawal.id}: Insufficient earnings (current: {driver_user.todays_earnings}, needed: {amount})")
                self.stdout.write(self.style.WARNING(f'Skipped {withdrawal.id}: Insufficient earnings'))
                continue

            with transaction.atomic():
                driver_user.todays_earnings -= amount
                driver_user.save()

                # Mark as processed to avoid re-processing
                withdrawal.processed_at = timezone.now()
                withdrawal.save()

                total_deducted += amount
                logger.info(f"Deducted ₦{amount} for withdrawal {withdrawal.id}. New earnings: ₦{driver_user.todays_earnings}")
                self.stdout.write(self.style.SUCCESS(f'Deducted ₦{amount} for withdrawal {withdrawal.id}'))

        self.stdout.write(self.style.SUCCESS(f'Processing complete. Total deducted: ₦{total_deducted}'))

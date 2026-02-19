from django.core.management.base import BaseCommand
from django.db import transaction
from django.utils import timezone
from users.models import WithdrawalRequest, DriverProfile, User
from decimal import Decimal
import logging

logger = logging.getLogger(__name__)

class Command(BaseCommand):
    help = 'Processes approved withdrawal requests that were not processed via the API. This is a fallback mechanism.'

    def handle(self, *args, **options):
        self.stdout.write(self.style.NOTICE('Starting fallback processing for approved withdrawals...'))
        
        # Find approved withdrawals that are still in 'pending' state for processing.
        # The API sets processed_at, so a null value indicates it was likely approved manually in the admin panel.
        approved_withdrawals = WithdrawalRequest.objects.filter(
            status='approved',
            processed_at__isnull=True
        ).select_related('driver_profile__user')

        if not approved_withdrawals.exists():
            self.stdout.write(self.style.SUCCESS('No approved withdrawals needing deduction found.'))
            return

        total_deducted = Decimal('0.00')
        for withdrawal in approved_withdrawals:
            driver_user = withdrawal.driver_profile.user
            driver_profile = withdrawal.driver_profile
            amount = withdrawal.amount

            # Use a transaction to ensure atomicity
            with transaction.atomic():
                # Re-fetch with select_for_update to lock the rows and prevent race conditions
                locked_profile = DriverProfile.objects.select_for_update().get(id=driver_profile.id)
                locked_user = locked_profile.user

                if locked_user.todays_earnings < amount:
                    logger.warning(f"Skipping deduction for withdrawal {withdrawal.id}: Insufficient earnings (current: {locked_user.todays_earnings}, needed: {amount})")
                    self.stdout.write(self.style.WARNING(f'Skipped withdrawal {withdrawal.id} for {driver_user.email}: Insufficient earnings.'))
                    continue

                # Deduct from earnings
                locked_user.todays_earnings -= amount
                locked_user.save(update_fields=['todays_earnings'])

                # Mark as processed to avoid re-processing
                withdrawal.processed_at = timezone.now()
                withdrawal.notes = "Processed by fallback management command."
                withdrawal.save(update_fields=['processed_at', 'notes'])

                total_deducted += amount
                logger.info(f"Deducted ₦{amount} for withdrawal {withdrawal.id}. New earnings for {locked_user.email}: ₦{locked_user.todays_earnings}")
                self.stdout.write(self.style.SUCCESS(f'Processed withdrawal {withdrawal.id}: Deducted ₦{amount} from {locked_user.email}'))

        self.stdout.write(self.style.SUCCESS(f'Processing complete. Total deducted: ₦{total_deducted}'))

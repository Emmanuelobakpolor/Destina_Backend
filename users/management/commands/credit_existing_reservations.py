from django.core.management.base import BaseCommand
from django.db.models import Sum
from django.utils import timezone
from users.models import Reservation, DriverProfile
from decimal import Decimal

class Command(BaseCommand):
    help = 'Backfills driver wallets and today\'s earnings from existing paid reservations.'

    def handle(self, *args, **options):
        self.stdout.write(self.style.SUCCESS("Starting backfill process for driver wallets..."))

        # Get all paid reservations that have a driver assigned
        paid_reservations = Reservation.objects.filter(status='paid', driver__isnull=False)

        if not paid_reservations.exists():
            self.stdout.write(self.style.WARNING("No paid reservations found to process."))
            return

        # Group reservations by driver profile
        reservations_by_driver = {}
        for r in paid_reservations:
            if r.driver_id not in reservations_by_driver:
                reservations_by_driver[r.driver_id] = []
            reservations_by_driver[r.driver_id].append(r)

        today = timezone.now().date()
        total_credited_amount = Decimal('0.0')

        for driver_profile_id, reservations in reservations_by_driver.items():
            try:
                driver_profile = DriverProfile.objects.get(id=driver_profile_id)
                
                # Calculate total earnings and today's earnings
                total_earnings = sum(res.amount for res in reservations)
                todays_earnings = sum(res.amount for res in reservations if res.created_at.date() == today)

                # Update the driver's profile wallet and user's today's earnings
                driver_profile.wallet = total_earnings
                driver_profile.user.todays_earnings = todays_earnings
                driver_profile.save(update_fields=['wallet'])
                driver_profile.user.save(update_fields=['todays_earnings'])

                self.stdout.write(self.style.SUCCESS(
                    f"Processed driver {driver_profile.user.email}: Total Wallet: ₦{total_earnings}, Today's Earnings: ₦{todays_earnings}"
                ))
                total_credited_amount += total_earnings

            except DriverProfile.DoesNotExist:
                self.stdout.write(self.style.ERROR(f"DriverProfile with ID {driver_profile_id} not found. Skipping."))

        self.stdout.write(
            self.style.SUCCESS(f"\nBackfill completed. Total amount credited across all drivers: ₦{total_credited_amount}")
        )

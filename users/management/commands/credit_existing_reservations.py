from django.core.management.base import BaseCommand
from django.db.models import Sum
from django.utils import timezone
from users.models import Reservation, DriverProfile
from decimal import Decimal

class Command(BaseCommand):
    help = 'Backfills driver total earnings from all paid reservations (no wallet updates).'

    def handle(self, *args, **options):
        self.stdout.write(self.style.SUCCESS("Starting backfill process for driver total earnings..."))

        # Get all paid reservations that have a driver assigned and an amount greater than zero
        paid_reservations = Reservation.objects.filter(driver__isnull=False, amount__gt=0, status='paid')

        if not paid_reservations.exists():
            self.stdout.write(self.style.WARNING("No reservations with assigned drivers found to process."))
            return

        # Group reservations by driver profile
        reservations_by_driver = {}
        for r in paid_reservations:
            if r.driver_id not in reservations_by_driver:
                reservations_by_driver[r.driver_id] = []
            reservations_by_driver[r.driver_id].append(r)

        total_earnings_amount = Decimal('0.0')

        for driver_profile_id, reservations in reservations_by_driver.items():
            try:
                driver_profile = DriverProfile.objects.get(id=driver_profile_id)
                
                # Calculate total earnings (all time)
                total_earnings = sum(res.amount for res in reservations)

                # Update user's total earnings (repurposed from todays_earnings)
                driver_profile.user.todays_earnings = total_earnings
                driver_profile.user.save(update_fields=['todays_earnings'])

                self.stdout.write(self.style.SUCCESS(
                    f"Updated earnings for driver {driver_profile.user.email}: Total: ₦{total_earnings}"
                ))
                total_earnings_amount += total_earnings

            except DriverProfile.DoesNotExist:
                self.stdout.write(self.style.ERROR(f"DriverProfile with ID {driver_profile_id} not found. Skipping."))

        self.stdout.write(
            self.style.SUCCESS(f"\nBackfill completed. Total earnings updated across all drivers: ₦{total_earnings_amount}")
        )

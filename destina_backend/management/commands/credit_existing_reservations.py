from django.core.management.base import BaseCommand
from django.contrib.auth import get_user_model
from users.models import Reservation

User = get_user_model()

class Command(BaseCommand):
    help = 'Credit drivers\' wallets for all existing paid reservations'

    def handle(self, *args, **options):
        drivers = User.objects.filter(role='driver')
        total_credited = 0

        for driver in drivers:
            # Get paid reservations for this driver
            paid_reservations = Reservation.objects.filter(
                driver__user=driver,
                status='paid'
            )
            
            if paid_reservations.exists():
                total_earnings = sum(reservation.amount for reservation in paid_reservations)
                driver.wallet = total_earnings
                driver.save(update_fields=['wallet'])
                
                self.stdout.write(
                    self.style.SUCCESS(
                        f"Credited ₦{total_earnings} to driver {driver.email} (ID: {driver.id}) from {paid_reservations.count()} reservations"
                    )
                )
                total_credited += total_earnings
            else:
                self.stdout.write(f"No paid reservations for driver {driver.email}")

        self.stdout.write(
            self.style.SUCCESS(f"Backfill completed. Total credited across all drivers: ₦{total_credited}")
        )

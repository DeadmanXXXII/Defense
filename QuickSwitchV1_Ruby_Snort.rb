# 3. Ruby with Snort IDS
- quick_switch_snort.rb ruby
# Quick Switch v1
# Compatible with IDS: Snort

puts "Executing IP configuration commands..."
system("ipconfig /release")
system("ipconfig /release6")
system("ipconfig /renew")
system("ipconfig /renew6")
system("ipconfig /flushdns")
puts "Task completed successfully."

# Footer
puts "Created by DeadmanXXXII"
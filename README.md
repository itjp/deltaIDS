<h1>Delta Intrusion Detection System</h1>
This is my mediocre attempt at a simple IDS, it is a way for me to learn more about Python and security and to make a program that has some sort of actual use, even though it may not be the most efficient. With time I hope to make this an effective IDS and give it as much functionality as any other alternative.

<h1>Usage</h1>
To learn more about the DeltaIDS type:
<code>
python deltaids.py -h
</code>

The easiest way to use DeltaIDS in a practical way would be to run
<code>
python deltaids.py -i
</code>
Which will store a base of the system, then to set up a cronjob to run 
<code>
python deltaids.py -c
</code>
This will compare the base system against your prior initializing scan.

<h1>ToDo</h1>
- Possibly Daemonize
- Add more functionality (DUH!)
- Ability to turn scans off and on through config.ini
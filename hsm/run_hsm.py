import time
import argparse

import m5
import m5.ticks
from m5.objects import *

from system import *

def parse_options():
    parser = argparse.ArgumentParser(description='Runs Keystone HSM PKCS#11 Test Suite in gem5')
    parser.add_argument("sbi", help='Path to opensbi binary with kernel payload')
    parser.add_argument("disk", help="Path to disk image")
    parser.add_argument("cpu_type", help="CPU model (timing or minor or atomic)")
    parser.add_argument("num_cpus", type=int, help="Number of CPU cores")

    return parser.parse_args()

def writeHsmScript(dir):
    file_name = '{}/run_hsm.sh'.format(dir)
    with open(file_name, "w+") as f:
        f.write('cd /root/ \n')
        f.write('insmod keystone-driver.ko \n')
        f.write('/sbin/m5 exit \n')
        f.write('./test_pkcs11_hsm hsm-eapp eyrie-rt \n')
        f.write('/sbin/m5 exit \n')
    return file_name

if __name__ == "__m5_main__":
    args = parse_options()

    system = RiscvSystem(args.sbi, args.disk, args.cpu_type, args.num_cpus)
    system.exit_on_work_items = True
    system.readfile = writeHsmScript(m5.options.outdir)

    root = Root(full_system = True, system = system)
    m5.disableAllListeners()
    m5.instantiate()

    print("Running Keystone HSM simulation in gem5...")
    exit_event = m5.simulate()

    if exit_event.getCause() == "m5_exit instruction encountered":
        print("Driver loaded! Starting Keystone HSM PKCS#11 test suite...")
        m5.stats.reset()
        start_tick = m5.curTick()
    else:
        print("Unexpected boot termination: " + exit_event.getCause())
        exit(1)

    exit_event = m5.simulate()

    if exit_event.getCause() == "m5_exit instruction encountered":
        print("Keystone HSM test suite completed successfully!")
        print("Dumping stats...")
        m5.stats.dump()
        end_tick = m5.curTick()
        m5.stats.reset()
        print("Simulated time: %.2fs" % ((end_tick - start_tick) / 1e12))
        exit(0)
    else:
        print("Unexpected termination: " + exit_event.getCause())
        exit(1)

import math

def meanstd(in_s):
    in_f = open(in_s, 'r')
    rows = []
    for line in in_f:
        key_v = int(line)
        rows += [key_v]
    E_X = (sum([ float(z) for z in rows ]) / len(rows))
    E_Xs = (sum([ float(z) * float(z) for z in rows ]) / len(rows))
            
    print ("%f" % (E_X / 1000000))
    print ("%f" % (math.sqrt(E_Xs - (E_X*E_X)) / 1000000))


def means(in_s, out_s, group_col = 0):
    in_f = open(in_s, 'r')
    grouper = {}
    for line in in_f:
        line = [i.strip() for i in line.split(",")]
        key_v = int(line[0])
        if key_v in grouper:
            grouper[key_v].append(line[1:])
        else:
            grouper[key_v] = [ line[1:] ]
    out_f = open(out_s, 'w')
    keys = sorted(grouper.keys())
    for group in keys:
        agg_value = list()
        rows = grouper[group]
        for i in range(0, len(rows[0])):
            E_X = (sum([ float(z[i]) for z in rows ]) / len(rows))
            E_Xs = (sum([ float(z[i]) * float(z[i]) for z in rows ]) / len(rows))
            
            agg_value.append("%f" % (E_X / 1000000000))
            agg_value.append("%f" % (math.sqrt(E_Xs - (E_X*E_X)) / 1000000000))
        out_f.write('%s, %s\n' % (group, ', '.join(agg_value)))
    out_f.close()
def max_s(in_s, out_s, group_col = 0):
    in_f = open(in_s, 'r')
    grouper = {}
    for line in in_f:
        line = [i.strip() for i in line.split(",")]
        key_v = int(line[0])
        if key_v in grouper:
            grouper[key_v].append(line[1:])
        else:
            grouper[key_v] = [ line[1:] ]
    out_f = open(out_s, 'w')
    keys = sorted(grouper.keys())
    for group in keys:
        agg_value = list()
        rows = grouper[group]
        for i in range(0, len(rows[0])):
            E_X = (max(*[ float(z[i]) for z in rows ]))
            
            agg_value.append("%f" % (E_X / 1000000))
#            agg_value.append("%f" % (math.sqrt(E_Xs - (E_X*E_X)) / 1000000))
        out_f.write('%s, %s\n' % (group, ', '.join(agg_value)))
    out_f.close()


if __name__ == "__main__":
    from sys import argv
    if argv[1] == 'means':
        assert len(argv) == 4
        means(*argv[2:])
    if argv[1] == 'max':
        assert len(argv) == 4
        max_s(*argv[2:])
    if argv[1] == 'meansingle':
        assert len(argv) == 3
        meanstd(argv[2])

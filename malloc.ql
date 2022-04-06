/**
 * @name variable-len-malloc
 * @id cpp/variable-len-malloc
 * @description identify malloc calls with + or * expressions in allocation
 * @precision high
 * @problem.severity warning
 * @kind problem
 */

import cpp

class MallocCall extends FunctionCall
{
    MallocCall() { this.getTarget().hasGlobalName("malloc") }
    Expr getAllocatedSize() {
        result = this.getArgument(0)
    }
}

from MallocCall malloc
where malloc.getAllocatedSize() instanceof AddExpr or malloc.getAllocatedSize() instanceof MulExpr
select malloc, "Potential Malloc Overflow: "

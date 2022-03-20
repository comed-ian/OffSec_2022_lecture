/**
 * @name variable-len-malloc
 * @id cpp/variable-len-malloc
 * @description identify variable length malloc calls
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
where malloc.getAllocatedSize() instanceof BinaryArithmeticOperation
select malloc, "Check variable-length malloc"
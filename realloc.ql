/**
 * @name variable-len-realloc
 * @id cpp/variable-len-realloc
 * @description identify variable length realloc calls
 * @precision high
 * @problem.severity warning
 * @kind problem
 */

import cpp

class ReallocCall extends FunctionCall
{
    ReallocCall() { this.getTarget().hasGlobalName("yyrealloc") }
    Expr getAllocatedSize() {
        result = this.getArgument(1)
    }
}

from ReallocCall realloc
where realloc.getAllocatedSize() instanceof BinaryArithmeticOperation
select realloc, "Check variable-length realloc"
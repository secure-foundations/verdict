// The main validation routine

use vstd::prelude::*;

use crate::backend::*;
use crate::checker::*;
use crate::trace::*;

verus! {

pub enum ValidationResult {
    Success(Theorem),

    /// backend succeeds but fails to produce a proof
    ProofFailure,

    /// backend fails to prove it
    BackendFailure,
}

/// Solve a goal and validate the result
/// The error type E should combine any errors from the backend
/// as well as ProofError
pub fn solve_and_validate<B: Backend, E: From<B::Error> + From<ProofError>>(
    backend: &mut B,
    program: &Program,
    goal: &Term,

    // Some options
    debug: bool,
    allow_unsupported_builtin: bool,
) -> (res: Result<ValidationResult, E>)
    ensures
        res matches Ok(ValidationResult::Success(thm)) ==> {
            &&& thm@.wf(program@)
            &&& thm@.stmt == goal@
        }
{
    let mut instance = backend.solve(program, goal)?;
    let mut validator = TraceValidator::new(program);

    {
        let mut events = instance.events()?;

        // Process all events until the goal is proven or the backend terminates
        loop invariant validator.wf(program@)
        {
            if let Some(event) = events.next()? {
                let thm = validator.process_event(&program, &event, debug, allow_unsupported_builtin, true)?;
                if (&thm.stmt).eq(goal) {
                    return Ok(ValidationResult::Success(thm.clone()));
                }
            } else {
                break;
            }
        }
    }

    if instance.proven()? {
        Ok(ValidationResult::ProofFailure)
    } else {
        Ok(ValidationResult::BackendFailure)
    }
}

}

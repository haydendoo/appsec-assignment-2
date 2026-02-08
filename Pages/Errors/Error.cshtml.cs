using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;

namespace appsec_assignment_2.Pages.Errors;

public class ErrorModel : PageModel
{
    public int ErrorCode { get; set; }

    public IActionResult OnGet(int? code)
    {
        ErrorCode = code ?? 0;
        if (ErrorCode == 403 || ErrorCode == 404 || ErrorCode == 500)
            return Redirect($"/Errors/{ErrorCode}");
        return Page();
    }
}

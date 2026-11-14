using HfDrive.Protocol;

namespace HfDrive.Desktop.ViewModels;

/// <summary>
/// Presentation wrapper for one owner reported by the provider through
/// <c>list_owners</c>. Nothing here is inferred or fabricated: the provider
/// reported these values for the signed-in person's verified identities.
/// </summary>
public sealed class OwnerViewModel
{
    public OwnerViewModel(Owner owner)
    {
        Owner = owner;
    }

    public Owner Owner { get; }

    public string HeaderDisplay
    {
        get
        {
            string name = string.IsNullOrEmpty(Owner.DisplayName) ? Owner.Namespace ?? Owner.OwnerId : Owner.DisplayName;
            string kind = Owner.OwnerKind == OwnerKind.Organization ? "Organization" : "Personal";
            return $"{name} ({kind})";
        }
    }

    public string NamespaceText => Owner.Namespace ?? "Canonical namespace not reported; this owner cannot be selected.";

    public string RoleText => string.IsNullOrEmpty(Owner.Role) ? "Role: not reported" : $"Role: {Owner.Role}";

    public string RestrictionsText => Owner.Restrictions.Count == 0
        ? "No restrictions reported (not an authorization guarantee)."
        : $"Reported restrictions: {string.Join(", ", Owner.Restrictions)}";

    public string CapabilityText =>
        Owner.CanCreate ? "Storage creation previously observed as permitted" : "Storage creation has not been verified.";
}

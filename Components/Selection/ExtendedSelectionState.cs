namespace Ptlk.RedisSnmp.Components.Selection;

public sealed class ExtendedSelectionState
{
    private readonly HashSet<string> selectedKeys;

    public ExtendedSelectionState(IEqualityComparer<string>? comparer = null)
    {
        selectedKeys = new HashSet<string>(comparer ?? StringComparer.Ordinal);
    }

    public IReadOnlySet<string> SelectedKeys => selectedKeys;

    public int Count => selectedKeys.Count;

    public string? AnchorKey { get; private set; }

    public string? FocusedKey { get; private set; }

    public bool IsSelected(string key) => selectedKeys.Contains(key);

    public void ApplyPointerSelection(
        IReadOnlyList<string> orderedKeys,
        string key,
        bool range,
        bool additive)
    {
        var targetIndex = IndexOf(orderedKeys, key);
        if (targetIndex < 0)
        {
            return;
        }

        if (range && AnchorKey is not null)
        {
            var anchorIndex = IndexOf(orderedKeys, AnchorKey);
            if (anchorIndex >= 0)
            {
                if (!additive)
                {
                    selectedKeys.Clear();
                }

                var start = Math.Min(anchorIndex, targetIndex);
                var end = Math.Max(anchorIndex, targetIndex);
                for (var index = start; index <= end; index++)
                {
                    selectedKeys.Add(orderedKeys[index]);
                }

                FocusedKey = key;
                return;
            }
        }

        if (additive)
        {
            if (!selectedKeys.Remove(key))
            {
                selectedKeys.Add(key);
            }
        }
        else
        {
            selectedKeys.Clear();
            selectedKeys.Add(key);
        }

        AnchorKey = key;
        FocusedKey = key;
    }

    public void SetFocus(string key, IReadOnlyList<string> orderedKeys)
    {
        if (IndexOf(orderedKeys, key) >= 0)
        {
            FocusedKey = key;
        }
    }

    public void SelectAll(IReadOnlyList<string> orderedKeys)
    {
        selectedKeys.Clear();
        selectedKeys.UnionWith(orderedKeys);
        AnchorKey = orderedKeys.Count > 0 ? orderedKeys[0] : null;
        FocusedKey = orderedKeys.Count > 0 ? orderedKeys[^1] : null;
    }

    public void Clear()
    {
        selectedKeys.Clear();
        AnchorKey = null;
        FocusedKey = null;
    }

    private int IndexOf(IReadOnlyList<string> orderedKeys, string key)
    {
        for (var index = 0; index < orderedKeys.Count; index++)
        {
            if (selectedKeys.Comparer.Equals(orderedKeys[index], key))
            {
                return index;
            }
        }

        return -1;
    }
}

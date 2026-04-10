#pragma once

#include "ViewBase.h"

class RegistryView : public ViewBase {
public:
	RegistryView();
	void BuildWindow();
	void Refresh();

private:
	struct RegistryValue {
		std::wstring Name;
		DWORD Type{ 0 };
		std::wstring TypeName;
		std::wstring DataText;
		std::wstring EditText;
		bool IsDefault{ false };
	};

	struct RegistryNode {
		std::wstring Name;
		std::wstring FullPath;
		HKEY RootKey{ nullptr };
		std::wstring SubKeyPath;
		bool Enumerated{ false };
		std::vector<std::unique_ptr<RegistryNode>> Children;
	};

	void BuildToolBar();
	void BuildContent();
	void BuildTreePane();
	void BuildNode(RegistryNode& node);
	void BuildValuesPane();
	void EnsureChildrenEnumerated(RegistryNode& node);
	void SelectNode(RegistryNode* node);
	void NavigateToPath(const std::wstring& path);
	void SelectValue(int index);
	void EnumerateValues();
	void OpenEditDialog(int index);
	bool ProbeWriteAccess() const;
	std::wstring GetEffectivePath() const;
	std::string GetAccessStatusText() const;
	void SyncEditorFromSelection();
	bool SaveSelectedValue();
	std::vector<std::unique_ptr<RegistryNode>> CreateHiveRoots() const;

	std::vector<std::unique_ptr<RegistryNode>> _roots;
	RegistryNode* _selectedNode{ nullptr };
	std::vector<RegistryValue> _values;
	int _selectedValueIndex{ -1 };
	int _editingValueIndex{ -1 };
	bool _openEditPopup{ false };
	bool _keyWritable{ false };
	char _editBuffer[2048]{};
	char _editStatus[256]{};
	char _pathBuffer[1024]{};
	bool _pathBufferDirty{ false };
	float _treePaneWidth{ 300.0f };
};

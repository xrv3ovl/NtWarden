#pragma once

#include "ViewBase.h"

class ObjectManagerView : public ViewBase {
public:
	struct ObjectEntry {
		std::wstring Name;
		std::wstring TypeName;
		std::wstring FullPath;
		std::wstring SymbolicLinkTarget;
		bool IsDirectory{ false };
	};

	struct DirectoryNode {
		std::wstring Name;
		std::wstring FullPath;
		std::vector<std::unique_ptr<DirectoryNode>> Children;
		std::vector<ObjectEntry> Objects;
	};

	ObjectManagerView();
	void BuildWindow();
	void Refresh();

private:
	void BuildToolBar();
	void BuildContent();
	void BuildTreePane();
	void BuildTreeNode(DirectoryNode& node);
	void BuildObjectListPane();
	void CollectObjects(DirectoryNode& node);
	void RebuildFlatCache();
	void SelectDirectory(DirectoryNode* node);
	void SelectDirectoryByPath(const std::wstring& path);
	DirectoryNode* FindDirectoryByPath(DirectoryNode& node, const std::wstring& path);
	bool JumpToTarget();

	std::unique_ptr<DirectoryNode> _root;
	DirectoryNode* _selectedDirectory{ nullptr };
	std::vector<ObjectEntry*> _flatObjects;
	std::wstring _selectedDirectoryPath{ L"\\" };
	std::wstring _selectedObjectPath;
	bool _listMode{ false };
	bool _showDirectories{ true };
	float _treePaneWidth{ 280.0f };
};

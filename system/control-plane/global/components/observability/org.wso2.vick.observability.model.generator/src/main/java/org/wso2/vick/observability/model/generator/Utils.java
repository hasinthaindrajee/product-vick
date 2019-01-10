/*
 *  Copyright (c) 2018, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *  WSO2 Inc. licenses this file to you under the Apache License,
 *  Version 2.0 (the "License"); you may not use this file except
 *  in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 *
 */
package org.wso2.vick.observability.model.generator;

import org.wso2.vick.observability.model.generator.model.Edge;

import java.util.HashSet;
import java.util.Set;

import static org.wso2.vick.observability.model.generator.Constants.EDGE_NAME_CONNECTOR;

/**
 * This is the Utils class that is used by other common components
 */
public class Utils {
    private Utils() {
    }

    public static String[] edgeNameElements(String edgeName) {
        return edgeName.split(EDGE_NAME_CONNECTOR);
    }

    public static String generateEdgeName(String parentNodeId, String childNodeId, String serviceName) {
        return parentNodeId + EDGE_NAME_CONNECTOR + childNodeId + EDGE_NAME_CONNECTOR + serviceName;
    }

    public static String getEdgePostFix(String edgeName) {
        int index = edgeName.lastIndexOf(Constants.LINK_SEPARATOR) + Constants.LINK_SEPARATOR.length();
        return edgeName.substring(index);
    }

    public static Set<Edge> getEdges(Set<String> edgeString) {
        Set<Edge> edges = new HashSet<>();
        for (String anEdge : edgeString) {
            edges.add(new Edge(anEdge));
        }
        return edges;
    }

    public static Set<String> getEdgesString(Set<Edge> edgeList) {
        Set<String> edges = new HashSet<>();
        for (Edge edge : edgeList) {
            edges.add(edge.getEdgeString());
        }
        return edges;
    }

    public static Node getNode(Set<Node> nodes, Node node) {
        for (Node setNode : nodes) {
            if (setNode.compareTo(node) == 0) {
                return setNode;
            }
        }
        return null;
    }

    public static String getQualifiedServiceName(String cellName, String serviceName) {
        return cellName + Constants.CELL_SERVICE_NAME_SEPARATOR + serviceName;
    }

    public static String getEdgeServiceName(String edgeString) {
        return edgeString.split(Constants.EDGE_NAME_CONNECTOR)[2];
    }

    public static String[] getServices(String serviceName) {
        return serviceName.split(Constants.LINK_SEPARATOR);
    }
}
